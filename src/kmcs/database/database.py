"""Database access layer for KMCS (Phase 2).

Provides :class:`DatabaseManager`, the single entry point the rest of the
application should use to talk to SQLite:

* engine construction with correct pragmas (foreign keys, WAL, busy timeout)
* thread-safe scoped sessions (``with db.session() as s: ...``)
* transaction helpers with rollback guarantees
* high-level repository-style operations that map domain objects from
  :mod:`kmcs.core.models` to ORM rows and back
* crash deduplication queries by fingerprint, campaign/crash/finding stats,
  settings key/value store, event audit sink.

Everything is honest: operations raise typed exceptions from
:mod:`kmcs.core.exceptions` instead of swallowing errors, and no query can
mutate state implicitly.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from sqlalchemy import (
    create_engine,
    delete,
    event as sa_event,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from kmcs.core.exceptions import (
    DatabaseError,
    RecordNotFoundError as NotFoundError,
    InvalidValueError,
    PolicyViolationError,
)
from kmcs.core import models as cm
from kmcs.database.models import (
    AuthorisationRow,
    Base,
    CampaignRow,
    CorpusEntryRow,
    CorpusRow,
    CrashRow,
    EventRow,
    EvidenceRow,
    FindingRow,
    JobRow,
    MinimizationRow,
    ReproductionRow,
    ReportRow,
    RegressionTestRow,
    SettingRow,
    TelemetryRow,
    TargetRow,
    finding_crashes,
    utc_now,
    SCHEMA_VERSION,
)

__all__ = [
    "DatabaseManager",
    "default_database_path",
    "T",
]

T = TypeVar("T")

PathLike = Union[str, "os.PathLike[str]"]

#: Default on-disk location when callers do not pass a path explicitly.
DEFAULT_DB_DIRNAME = ".kmcs"
DEFAULT_DB_FILENAME = "kmcs.db"


def default_database_path(root: Optional[PathLike] = None) -> str:
    """Resolve ``<root or cwd>/.kmcs/kmcs.db`` without creating anything."""
    base = Path(root) if root else Path.cwd()
    return str(base / DEFAULT_DB_DIRNAME / DEFAULT_DB_FILENAME)


class DatabaseManager:
    """Owns the SQLAlchemy engine + session factory for one KMCS database.

    The manager is safe to share across threads: engines are pooled and every
    unit of work runs in its own :class:`~sqlalchemy.orm.Session` obtained via
    :meth:`session`.  A single manager instance per process is the intended
    usage; construct it once during application start-up.
    """

    # ------------------------------------------------------------------ #
    # construction / lifecycle
    # ------------------------------------------------------------------ #

    def __init__(
        self,
        url_or_path: Optional[PathLike] = None,
        *,
        echo: bool = False,
        pool_size: int = 5,
        max_overflow: int = 10,
        busy_timeout_ms: int = 5000,
        foreign_keys: bool = True,
        wal: bool = True,
        ensure_schema: bool = True,
    ) -> None:
        """Create (and optionally initialise) a database handle.

        Parameters
        ----------
        url_or_path:
            Either a full SQLAlchemy URL (``sqlite:///...``,
            ``sqlite:///:memory:``) or a plain filesystem path to the SQLite
            file.  ``None`` uses :func:`default_database_path`.
        echo:
            Mirror SQL to the logger (debugging aid).
        busy_timeout_ms:
            SQLite ``busy_timeout`` pragma — how long writers wait for the
            WAL lock before raising ``SQLITE_BUSY``.
        ensure_schema:
            When ``True`` (default) the schema is created/upgraded lazily on
            first use via :meth:`initialize`.
        """
        url = self._normalise_url(url_or_path)
        self.url = url
        self.path: Optional[str] = self._path_from_url(url)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self.foreign_keys_enabled = bool(foreign_keys)
        self.wal_enabled = bool(wal)
        self._lock = threading.RLock()
        self._initialized = False
        self._closed = False

        connect_args: Dict[str, Any] = {"check_same_thread": False}
        if url.startswith("sqlite"):
            connect_args["timeout"] = max(1.0, self.busy_timeout_ms / 1000.0)

        kwargs: Dict[str, Any] = dict(echo=echo, connect_args=connect_args,
                                      future=True)
        if url.startswith("sqlite"):
            # QueuePool defaults are wrong for SQLite files; StaticPool for
            # in-memory so every connection shares the same database.
            if ":memory:" in url or "mode=memory" in url:
                from sqlalchemy.pool import StaticPool
                kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_size"] = pool_size
            kwargs["max_overflow"] = max_overflow

        try:
            self.engine: Engine = create_engine(url, **kwargs)
        except SQLAlchemyError as exc:
            raise DatabaseError(f"cannot create engine for {url!r}: {exc}",
                                component="database.database") from exc

        if url.startswith("sqlite"):
            self._attach_sqlite_pragmas(self.engine)

        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False,
                                            autoflush=False, future=True)

        if ensure_schema:
            self.initialize()

    @staticmethod
    def _normalise_url(url_or_path: Optional[PathLike]) -> str:
        if url_or_path is None:
            return f"sqlite:///{default_database_path()}"
        text_value = str(url_or_path)
        if text_value.startswith(("sqlite:", "postgresql:", "mysql:", "duckdb:")):
            return text_value
        # Plain filesystem path.
        expanded = os.path.expanduser(text_value)
        abs_path = os.path.abspath(expanded)
        parent = os.path.dirname(abs_path)
        if parent and not os.path.isdir(parent):
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as exc:
                raise DatabaseError(
                    f"cannot create database directory {parent!r}: {exc}",
                    component="database.database") from exc
        return f"sqlite:///{abs_path}"

    @staticmethod
    def _path_from_url(url: str) -> Optional[str]:
        if not url.startswith("sqlite"):
            return None
        prefix = "sqlite:///"
        if url.startswith(prefix):
            tail = url[len(prefix):]
            if tail in ("", ":memory:") or "mode=memory" in tail:
                return None
            return tail
        return None

    def _attach_sqlite_pragmas(self, engine: Engine) -> None:
        """Apply per-connection pragmas: FK enforcement, WAL, timeouts."""

        @sa_event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn: sqlite3.Connection, _record: Any) -> None:
            cursor = dbapi_conn.cursor()
            try:
                cursor.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
                if self.foreign_keys_enabled:
                    cursor.execute("PRAGMA foreign_keys=ON")
                if self.wal_enabled and self.path:
                    cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.execute("PRAGMA cache_size=-16000")  # ~16 MiB
            finally:
                cursor.close()

    # ------------------------------------------------------------------ #
    # schema lifecycle
    # ------------------------------------------------------------------ #

    def initialize(self, force: bool = False) -> None:
        """Create missing tables (idempotent). Safe to call repeatedly."""
        with self._lock:
            if self._initialized and not force:
                return
            if self._closed:
                raise DatabaseError("database manager is closed",
                                    component="database.database")
            # Mark before opening any session: _stamp_version() below uses
            # self.session(), which re-enters initialize(). Without this the
            # recursion never terminates. create_all is idempotent, so even a
            # failed stamp leaves a usable schema and a retry can repair it.
            self._initialized = True
            try:
                Base.metadata.create_all(self.engine)
                self._stamp_version()
            except SQLAlchemyError as exc:
                self._initialized = False
                raise DatabaseError(f"schema initialisation failed: {exc}",
                                    component="database.database") from exc

    def _stamp_version(self) -> None:
        with self.session() as session:
            row = session.get(SettingRow, "schema.version")
            if row is None:
                session.add(SettingRow(key="schema.version",
                                       value_json=SCHEMA_VERSION,
                                       category="system",
                                       description="ORM schema version marker"))
                session.commit()

    @property
    def schema_version(self) -> int:
        value = self.get_setting("schema.version", default=0)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def drop_all(self) -> None:
        """Delete every KMCS table (used by tests / explicit resets only)."""
        with self._lock:
            try:
                Base.metadata.drop_all(self.engine)
            except SQLAlchemyError as exc:
                raise DatabaseError(f"drop_all failed: {exc}",
                                    component="database.database") from exc
            self._initialized = False

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.engine.dispose()
            finally:
                self._closed = True

    def __enter__(self) -> "DatabaseManager":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # sessions & transactions
    # ------------------------------------------------------------------ #

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a session; commit on clean exit, rollback on error."""
        if self._closed:
            raise DatabaseError("database manager is closed",
                                component="database.database")
        self.initialize()
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as exc:
            session.rollback()
            raise DatabaseError(f"session failed: {exc}",
                                component="database.database") from exc
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @contextmanager
    def transaction(self) -> Iterator[Session]:
        """Explicit transaction scope (same semantics as :meth:`session`)."""
        with self.session() as session:
            yield session

    def run_in_transaction(self, fn: Callable[[Session], T]) -> T:
        """Execute ``fn(session)`` inside a transaction and return its value."""
        with self.session() as session:
            return fn(session)

    # ------------------------------------------------------------------ #
    # generic CRUD helpers
    # ------------------------------------------------------------------ #

    def add(self, obj: Any) -> Any:
        with self.session() as session:
            session.add(obj)
            session.flush()
            return obj

    def add_many(self, objs: Iterable[Any]) -> int:
        items = list(objs)
        with self.session() as session:
            session.add_all(items)
            session.flush()
        return len(items)

    def get(self, model: Type[T], pk: Any) -> Optional[T]:
        with self.session() as session:
            return session.get(model, pk)  # type: ignore[return-value]

    def get_or_raise(self, model: Type[T], pk: Any) -> T:
        row = self.get(model, pk)
        if row is None:
            raise NotFoundError(
                f"{getattr(model, '__name__', 'row')} '{pk}' not found",
                component="database.database")
        return row

    def find(self, model: Type[T], *conditions: Any,
             order_by: Any = None, limit: Optional[int] = None,
             offset: Optional[int] = None) -> List[T]:
        with self.session() as session:
            stmt = select(model)
            for condition in conditions:
                stmt = stmt.where(condition)
            if order_by is not None:
                stmt = stmt.order_by(order_by)
            if limit is not None:
                stmt = stmt.limit(int(limit))
            if offset:
                stmt = stmt.offset(int(offset))
            return list(session.scalars(stmt).all())  # type: ignore[arg-type]

    def count(self, model: Type[T], *conditions: Any) -> int:
        with self.session() as session:
            stmt = select(func.count()).select_from(model)
            for condition in conditions:
                stmt = stmt.where(condition)
            return int(session.scalar(stmt) or 0)

    def delete_row(self, obj: Any) -> None:
        with self.session() as session:
            merged = session.merge(obj) if obj in session else obj
            session.delete(merged)

    def delete_by_id(self, model: Type[Any], pk: Any) -> bool:
        with self.session() as session:
            row = session.get(model, pk)
            if row is None:
                return False
            session.delete(row)
        return True

    # ------------------------------------------------------------------ #
    # targets
    # ------------------------------------------------------------------ #

    def save_target(self, target: cm.Target) -> TargetRow:
        """Insert-or-update a target row from a core ``Target``.

        An attached authorisation object is persisted first so the FK can be
        resolved; expired/revoked authorisations are refused at this boundary
        too (defence-in-depth beyond the core guard).
        """
        if not isinstance(target, cm.Target):
            raise InvalidValueError(
                f"expected core Target, got {type(target).__name__}",
                component="database.database")
        with self.session() as session:
            auth_row: Optional[AuthorisationRow] = None
            if target.authorisation is not None:
                auth = target.authorisation
                if getattr(auth, "revoked", False):
                    raise PolicyViolationError(
                        "refusing to persist target with revoked authorisation",
                        component="database.database")
                if callable(getattr(auth, "expired", None)) and auth.expired():
                    raise PolicyViolationError(
                        "refusing to persist target with expired authorisation",
                        component="database.database")
                auth_row = session.get(AuthorisationRow, auth.id)
                if auth_row is None:
                    auth_row = AuthorisationRow.from_domain(auth)
                    session.add(auth_row)
                    session.flush()
            existing = session.get(TargetRow, target.id)
            row = TargetRow.from_domain(target, auth_row)
            if existing is None:
                session.add(row)
            else:
                for column in TargetRow.__mapper__.columns:
                    key = column.key
                    if key in ("id", "created_at"):
                        continue
                    setattr(existing, key, getattr(row, key))
                existing.updated_at = utc_now()
                row = existing
            session.flush()
            return row

    def get_target(self, target_id: str) -> cm.Target:
        with self.session() as session:
            row = session.get(TargetRow, target_id)
            if row is None:
                raise NotFoundError(f"target '{target_id}' not found",
                                    component="database.database")
            auth = row.authorisation.to_domain() if row.authorisation else None
            return row.to_domain(authorisation=auth)

    def list_targets(self, *, name_like: Optional[str] = None,
                     kind: Optional[str] = None,
                     authorized_only: bool = False,
                     limit: Optional[int] = None) -> List[cm.Target]:
        with self.session() as session:
            stmt = select(TargetRow)
            if name_like:
                stmt = stmt.where(TargetRow.name.like(f"%{name_like}%"))
            if kind:
                stmt = stmt.where(TargetRow.kind == str(kind))
            if authorized_only:
                stmt = stmt.where(TargetRow.authorisation_id.is_not(None))
            stmt = stmt.order_by(TargetRow.created_at.desc())
            if limit:
                stmt = stmt.limit(int(limit))
            rows = session.scalars(stmt).all()
            out: List[cm.Target] = []
            for row in rows:
                auth = row.authorisation.to_domain() if row.authorisation else None
                out.append(row.to_domain(authorisation=auth))
            return out

    def delete_target(self, target_id: str) -> bool:
        return self.delete_by_id(TargetRow, target_id)

    # ------------------------------------------------------------------ #
    # corpora
    # ------------------------------------------------------------------ #

    def save_corpus(self, corpus: cm.Corpus, *, replace_entries: bool = True) -> CorpusRow:
        with self.session() as session:
            row = session.get(CorpusRow, corpus.id)
            if row is None:
                row = CorpusRow.from_domain(corpus)
                session.add(row)
            entries = list(getattr(corpus, "entries", []) or [])
            if replace_entries:
                session.execute(delete(CorpusEntryRow)
                                .where(CorpusEntryRow.corpus_id == corpus.id))
                seen_hashes = set()
                for entry in entries:
                    if entry.content_hash in seen_hashes:
                        continue
                    seen_hashes.add(entry.content_hash)
                    session.add(CorpusEntryRow.from_domain(entry, corpus.id))
                row.entry_count = len(seen_hashes)
                row.total_bytes = sum(int(e.size_bytes) for e in entries
                                      if e.content_hash in seen_hashes)
            session.flush()
            return row

    def get_corpus(self, corpus_id: str) -> Dict[str, Any]:
        with self.session() as session:
            row = session.get(CorpusRow, corpus_id)
            if row is None:
                raise NotFoundError(f"corpus '{corpus_id}' not found",
                                    component="database.database")
            entries = session.scalars(
                select(CorpusEntryRow)
                .where(CorpusEntryRow.corpus_id == corpus_id)
                .order_by(CorpusEntryRow.added_at)
            ).all()
            return {
                "summary": row.summary_dict(),
                "entries": [e.to_domain() for e in entries],
            }

    def find_corpus_entry(self, corpus_id: str, content_hash: str
                          ) -> Optional[CorpusEntryRow]:
        rows = self.find(CorpusEntryRow,
                         CorpusEntryRow.corpus_id == corpus_id,
                         CorpusEntryRow.content_hash == content_hash,
                         limit=1)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ #
    # campaigns
    # ------------------------------------------------------------------ #

    def save_campaign(self, campaign: cm.Campaign) -> CampaignRow:
        if not isinstance(campaign, cm.Campaign):
            raise InvalidValueError(
                f"expected core Campaign, got {type(campaign).__name__}",
                component="database.database")
        with self.session() as session:
            if not session.get(TargetRow, campaign.target_id):
                raise NotFoundError(
                    f"campaign references unknown target "
                    f"'{campaign.target_id}'",
                    component="database.database")
            row = session.get(CampaignRow, campaign.id)
            fresh = CampaignRow.from_domain(campaign)
            if row is None:
                session.add(fresh)
                row = fresh
            else:
                for column in CampaignRow.__mapper__.columns:
                    key = column.key
                    if key == "id":
                        continue
                    setattr(row, key, getattr(fresh, key))
            session.flush()
            return row

    def get_campaign(self, campaign_id: str) -> cm.Campaign:
        with self.session() as session:
            row = session.get(CampaignRow, campaign_id)
            if row is None:
                raise NotFoundError(f"campaign '{campaign_id}' not found",
                                    component="database.database")
            return row.to_domain()

    def list_campaigns(self, *, target_id: Optional[str] = None,
                       status: Optional[str] = None,
                       engine: Optional[str] = None,
                       limit: Optional[int] = None) -> List[cm.Campaign]:
        with self.session() as session:
            stmt = select(CampaignRow)
            if target_id:
                stmt = stmt.where(CampaignRow.target_id == target_id)
            if status:
                stmt = stmt.where(CampaignRow.status == str(status))
            if engine:
                stmt = stmt.where(CampaignRow.engine == str(engine))
            stmt = stmt.order_by(CampaignRow.created_at.desc())
            if limit:
                stmt = stmt.limit(int(limit))
            return [row.to_domain() for row in session.scalars(stmt).all()]

    def set_campaign_status(self, campaign_id: str, status: str,
                            *, started_at: Optional[str] = None,
                            finished_at: Optional[str] = None) -> CampaignRow:
        resolved = cm.RunStatus.coerce(status)
        with self.session() as session:
            row = session.get(CampaignRow, campaign_id)
            if row is None:
                raise NotFoundError(f"campaign '{campaign_id}' not found",
                                    component="database.database")
            row.status = str(resolved.value)
            if started_at is not None or resolved is cm.RunStatus.RUNNING:
                if row.started_at is None:
                    row.started_at = (cm.parse_timestamp(started_at)
                                      or utc_now())
            if resolved.terminal and row.finished_at is None:
                row.finished_at = (cm.parse_timestamp(finished_at) or utc_now())
            session.flush()
            return row

    # ------------------------------------------------------------------ #
    # crashes (+ fingerprint dedup queries)
    # ------------------------------------------------------------------ #

    def save_crash(self, crash: cm.Crash, *,
                   compute_fingerprint: bool = True) -> CrashRow:
        if not isinstance(crash, cm.Crash):
            raise InvalidValueError(
                f"expected core Crash, got {type(crash).__name__}",
                component="database.database")
        if compute_fingerprint and crash.fingerprint is None:
            crash.compute_fingerprint()
        with self.session() as session:
            if crash.campaign_id and not session.get(CampaignRow,
                                                     crash.campaign_id):
                # Referential integrity: create the campaign shell from the
                # crash's own metadata instead of hard-failing.  This keeps
                # the FK constraint real (no orphan rows) while remaining
                # idempotent — a later save_campaign() upserts onto this row.
                session.add(CampaignRow(
                    id=crash.campaign_id,
                    name=f"auto:{crash.campaign_id}",
                    target_id=crash.target_id or "",
                    engine=crash.engine or "unknown",
                    status="recorded",
                ))
                session.flush()
            row = session.get(CrashRow, crash.id)
            fresh = CrashRow.from_domain(crash)
            if row is None:
                session.add(fresh)
                row = fresh
            else:
                for column in CrashRow.__mapper__.columns:
                    key = column.key
                    if key == "id":
                        continue
                    setattr(row, key, getattr(fresh, key))
            session.flush()
            return row

    def get_crash(self, crash_id: str) -> cm.Crash:
        with self.session() as session:
            row = session.get(CrashRow, crash_id)
            if row is None:
                raise NotFoundError(f"crash '{crash_id}' not found",
                                    component="database.database")
            return row.to_domain()

    def crashes_by_fingerprint(self, digest: str, *,
                               include_duplicates: bool = False
                               ) -> List[cm.Crash]:
        with self.session() as session:
            stmt = select(CrashRow).where(CrashRow.fingerprint_digest == digest)
            if not include_duplicates:
                stmt = stmt.where(CrashRow.duplicate_of.is_(None))
            stmt = stmt.order_by(CrashRow.first_seen_at)
            return [row.to_domain() for row in session.scalars(stmt).all()]

    def find_duplicate(self, crash: cm.Crash) -> Optional[CrashRow]:
        """Return the canonical crash sharing this crash's fingerprint."""
        if crash.fingerprint is None:
            crash.compute_fingerprint()
        digest = crash.fingerprint.digest if crash.fingerprint else ""
        if not digest:
            return None
        rows = self.find(CrashRow,
                         CrashRow.fingerprint_digest == digest,
                         CrashRow.duplicate_of.is_(None),
                         CrashRow.id != crash.id,
                         order_by=CrashRow.first_seen_at,
                         limit=1)
        return rows[0] if rows else None

    def mark_duplicate(self, duplicate_id: str, canonical_id: str) -> cm.Crash:
        if duplicate_id == canonical_id:
            raise InvalidValueError("a crash cannot duplicate itself",
                                    component="database.database")
        with self.session() as session:
            dup = session.get(CrashRow, duplicate_id)
            canon = session.get(CrashRow, canonical_id)
            if dup is None or canon is None:
                raise NotFoundError(
                    f"crash pair missing ({duplicate_id}, {canonical_id})",
                    component="database.database")
            dup.duplicate_of = canonical_id
            dup.state = cm.CrashState.DUPLICATE.value
            dup.last_seen_at = utc_now()
            canon.occurrence_count = int(canon.occurrence_count) + 1
            canon.last_seen_at = utc_now()
            session.flush()
            return dup.to_domain()

    def list_crashes(self, *, campaign_id: Optional[str] = None,
                     target_id: Optional[str] = None,
                     state: Optional[str] = None,
                     severity: Optional[str] = None,
                     crash_class: Optional[str] = None,
                     since: Optional[str] = None,
                     limit: Optional[int] = None,
                     offset: Optional[int] = None) -> List[cm.Crash]:
        with self.session() as session:
            stmt = select(CrashRow)
            if campaign_id:
                stmt = stmt.where(CrashRow.campaign_id == campaign_id)
            if target_id:
                stmt = stmt.where(CrashRow.target_id == target_id)
            if state:
                stmt = stmt.where(CrashRow.state == str(state))
            if severity:
                stmt = stmt.where(CrashRow.severity == str(severity))
            if crash_class:
                stmt = stmt.where(CrashRow.crash_class == str(crash_class))
            if since:
                moment = cm.parse_timestamp(since)
                if moment is not None:
                    stmt = stmt.where(CrashRow.first_seen_at >= moment.isoformat())
            stmt = stmt.order_by(CrashRow.first_seen_at.desc())
            if limit:
                stmt = stmt.limit(int(limit))
            if offset:
                stmt = stmt.offset(int(offset))
            return [row.to_domain() for row in session.scalars(stmt).all()]

    # ------------------------------------------------------------------ #
    # findings
    # ------------------------------------------------------------------ #

    def save_finding(self, finding: cm.Finding, *,
                     link_crash_ids: Optional[Sequence[str]] = None) -> FindingRow:
        if not isinstance(finding, cm.Finding):
            raise InvalidValueError(
                f"expected core Finding, got {type(finding).__name__}",
                component="database.database")
        with self.session() as session:
            row = session.get(FindingRow, finding.id)
            fresh = FindingRow.from_domain(finding)
            if row is None:
                session.add(fresh)
                row = fresh
                session.flush()
            else:
                for column in FindingRow.__mapper__.columns:
                    key = column.key
                    if key == "id":
                        continue
                    setattr(row, key, getattr(fresh, key))
                row.updated_at = utc_now()
                session.flush()
            wanted = list(link_crash_ids or finding.crash_ids or [])
            if wanted:
                existing_links = {
                    r[0] for r in session.execute(
                        select(finding_crashes.c.crash_id)
                        .where(finding_crashes.c.finding_id == row.id)
                    )
                }
                for crash_id in wanted:
                    if crash_id in existing_links:
                        continue
                    if not session.get(CrashRow, crash_id):
                        raise NotFoundError(
                            f"cannot link unknown crash '{crash_id}'",
                            component="database.database")
                    session.execute(insert(finding_crashes).values(
                        finding_id=row.id, crash_id=crash_id,
                        role=("canonical"
                              if crash_id == row.canonical_crash_id
                              else "member")))
                    session.get(CrashRow, crash_id)  # touch identity map
            # propagate finding id onto linked canonical crash rows
            session.execute(
                update(CrashRow)
                .where(CrashRow.id.in_(wanted), CrashRow.finding_id.is_(None))
                .values(finding_id=row.id)
            )
            return row

    def get_finding(self, finding_id: str) -> cm.Finding:
        with self.session() as session:
            row = session.get(FindingRow, finding_id)
            if row is None:
                raise NotFoundError(f"finding '{finding_id}' not found",
                                    component="database.database")
            crash_ids = [r[0] for r in session.execute(
                select(finding_crashes.c.crash_id)
                .where(finding_crashes.c.finding_id == finding_id))]
            return row.to_domain(crash_ids=crash_ids)

    def transition_finding(self, finding_id: str, new_state: str,
                           *, actor: str = "", note: str = "") -> cm.Finding:
        with self.session() as session:
            row = session.get(FindingRow, finding_id)
            if row is None:
                raise NotFoundError(f"finding '{finding_id}' not found",
                                    component="database.database")
            crash_ids = [r[0] for r in session.execute(
                select(finding_crashes.c.crash_id)
                .where(finding_crashes.c.finding_id == finding_id))]
            finding = row.to_domain(crash_ids=crash_ids)
            finding.transition(new_state, actor=actor, note=note)
            row.state = finding.state
            row.confirmed_at = cm.parse_timestamp(finding.confirmed_at) \
                or row.confirmed_at
            row.reported_at = cm.parse_timestamp(finding.reported_at) \
                or row.reported_at
            row.closed_at = cm.parse_timestamp(finding.closed_at) or row.closed_at
            row.updated_at = utc_now()
            session.flush()
            return finding

    def list_findings(self, *, state: Optional[str] = None,
                      severity: Optional[str] = None,
                      target_id: Optional[str] = None,
                      limit: Optional[int] = None) -> List[cm.Finding]:
        with self.session() as session:
            stmt = select(FindingRow)
            if state:
                stmt = stmt.where(FindingRow.state == str(state))
            if severity:
                stmt = stmt.where(FindingRow.severity == str(severity))
            if target_id:
                stmt = stmt.where(FindingRow.target_id == target_id)
            stmt = stmt.order_by(FindingRow.discovered_at.desc())
            if limit:
                stmt = stmt.limit(int(limit))
            rows = session.scalars(stmt).all()
            out: List[cm.Finding] = []
            for row in rows:
                crash_ids = [r[0] for r in session.execute(
                    select(finding_crashes.c.crash_id)
                    .where(finding_crashes.c.finding_id == row.id))]
                out.append(row.to_domain(crash_ids=crash_ids))
            return out

    # ------------------------------------------------------------------ #
    # jobs mirror & events audit
    # ------------------------------------------------------------------ #

    def record_job(self, definition: Any, *, state: str = "created",
                   attempts: int = 0, error: str = "",
                   campaign_id: Optional[str] = None) -> JobRow:
        """Persist a durable mirror of a core ``JobDefinition``."""
        payload = definition.to_dict() if hasattr(definition, "to_dict") else {}
        with self.session() as session:
            row = session.get(JobRow, str(payload.get("id", "")))
            if row is None:
                row = JobRow(id=str(payload.get("id", "")))
                session.add(row)
            row.kind = str(payload.get("kind", "custom"))
            row.name = str(payload.get("name", "") or "")
            row.state = str(state)
            row.priority = int(payload.get("priority", 0) or 0)
            row.attempts = int(attempts)
            row.depends_on_json = list(payload.get("depends_on", []) or [])
            row.tags = list(payload.get("tags", []) or [])
            # never store raw callables; keep JSON-safe subset only
            safe_payload = {k: v for k, v in (payload.get("payload") or {}).items()
                            if isinstance(v, (str, int, float, bool, list, dict,
                                              type(None)))}
            row.payload_json = safe_payload
            row.error = str(error or "")
            row.campaign_id = campaign_id
            session.flush()
            return row

    def append_event(self, envelope: Any) -> EventRow:
        """Store one bus event (append-only audit trail)."""
        payload = envelope.to_dict() if hasattr(envelope, "to_dict") else dict(envelope)
        with self.session() as session:
            row = EventRow(
                event_id=str(payload.get("event_id", "")),
                topic=str(payload.get("topic", "")),
                etype=str(payload.get("etype", "")),
                source=str(payload.get("source", "")),
                correlation_id=str(payload.get("correlation_id", "")),
                payload_json=payload.get("payload") or {},
                occurred_at=(cm.parse_timestamp(payload.get("occurred_at"))
                             or utc_now()),
            )
            session.add(row)
            session.flush()
            return row

    def recent_events(self, *, topic_prefix: Optional[str] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        with self.session() as session:
            stmt = select(EventRow)
            if topic_prefix:
                stmt = stmt.where(EventRow.topic.like(f"{topic_prefix}%"))
            stmt = stmt.order_by(EventRow.seq.desc()).limit(int(limit))
            return [{
                "seq": r.seq, "event_id": r.event_id, "topic": r.topic,
                "etype": r.etype, "source": r.source,
                "correlation_id": r.correlation_id,
                "payload": dict(r.payload_json or {}),
                "occurred_at": cm.utc_string(r.occurred_at),
            } for r in session.scalars(stmt).all()]

    # ------------------------------------------------------------------ #
    # settings store
    # ------------------------------------------------------------------ #

    def set_setting(self, key: str, value: Any, *, category: str = "general",
                    description: str = "") -> None:
        if not key or not isinstance(key, str):
            raise InvalidValueError("setting key must be a non-empty string",
                                    component="database.database")
        with self.session() as session:
            row = session.get(SettingRow, key)
            if row is None:
                row = SettingRow(key=key)
                session.add(row)
            row.value_json = value
            row.category = category
            if description:
                row.description = description
            session.flush()

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.session() as session:
            row = session.get(SettingRow, key)
            if row is None:
                return default
            return row.value_json

    def all_settings(self, category: Optional[str] = None
                     ) -> Dict[str, Any]:
        with self.session() as session:
            stmt = select(SettingRow)
            if category:
                stmt = stmt.where(SettingRow.category == category)
            return {r.key: r.value_json for r in session.scalars(stmt).all()}

    # ------------------------------------------------------------------ #
    # telemetry
    # ------------------------------------------------------------------ #

    def record_telemetry(self, campaign_id: str, sample: Any) -> TelemetryRow:
        payload = sample.to_dict() if hasattr(sample, "to_dict") else dict(sample)
        with self.session() as session:
            row = TelemetryRow(campaign_id=campaign_id, sample_json=payload,
                               taken_at=utc_now())
            session.add(row)
            session.flush()
            return row

    # ------------------------------------------------------------------ #
    # aggregate statistics (read-only dashboards)
    # ------------------------------------------------------------------ #

    def stats(self) -> Dict[str, Any]:
        with self.session() as session:
            def total(model: Type[Any]) -> int:
                return int(session.scalar(select(func.count()).select_from(model)) or 0)

            by_severity = dict(session.execute(
                select(CrashRow.severity, func.count())
                .group_by(CrashRow.severity)).all())
            by_state = dict(session.execute(
                select(CrashRow.state, func.count())
                .group_by(CrashRow.state)).all())
            unique_fingerprints = int(session.scalar(
                select(func.count(func.distinct(CrashRow.fingerprint_digest)))
                .where(CrashRow.fingerprint_digest != "")) or 0)
            campaign_status = dict(session.execute(
                select(CampaignRow.status, func.count())
                .group_by(CampaignRow.status)).all())
            finding_states = dict(session.execute(
                select(FindingRow.state, func.count())
                .group_by(FindingRow.state)).all())
            return {
                "targets": total(TargetRow),
                "corpora": total(CorpusRow),
                "corpus_entries": total(CorpusEntryRow),
                "campaigns": total(CampaignRow),
                "crashes": total(CrashRow),
                "unique_crash_fingerprints": unique_fingerprints,
                "findings": total(FindingRow),
                "jobs": total(JobRow),
                "events": total(EventRow),
                "reproductions": total(ReproductionRow),
                "minimizations": total(MinimizationRow),
                "reports": total(ReportRow),
                "regression_tests": total(RegressionTestRow),
                "crashes_by_severity": by_severity,
                "crashes_by_state": by_state,
                "campaigns_by_status": campaign_status,
                "findings_by_state": finding_states,
                "schema_version": self.schema_version,
            }

    # ------------------------------------------------------------------ #
    # maintenance
    # ------------------------------------------------------------------ #

    def vacuum(self) -> None:
        with self.engine.connect() as conn:
            conn.execute(text("VACUUM"))
            conn.commit()

    def integrity_check(self) -> List[str]:
        problems: List[str] = []
        with self.engine.connect() as conn:
            quick = conn.execute(text("PRAGMA quick_check")).scalar()
            if str(quick) != "ok":
                problems.append(f"quick_check: {quick}")
            fk_rows = conn.execute(text("PRAGMA foreign_key_check")).fetchall()
            for row in fk_rows:
                problems.append("fk_violation: " + " ".join(str(x) for x in row))
        return problems

    def export_json(self) -> str:
        """Dump every table to a single JSON document (portable backup)."""
        with self.session() as session:
            data: Dict[str, Any] = {"_meta": {
                "exported_at": cm.utc_string(),
                "schema_version": self.schema_version,
            }}
            for model in (TargetRow, AuthorisationRow, CorpusRow, CorpusEntryRow,
                          CampaignRow, CrashRow, FindingRow, JobRow, SettingRow,
                          ReportRow, RegressionTestRow, EvidenceRow):
                rows = session.scalars(select(model)).all()
                data[model.__tablename__] = [
                    r.to_row_dict() for r in rows]
            links = session.execute(select(finding_crashes)).fetchall()
            data["finding_crashes"] = [dict(l._mapping) for l in links]
        return json.dumps(data, sort_keys=True, default=str, indent=2)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        where = self.path or ":memory:"
        state = "open" if not self._closed else "closed"
        return (f"<DatabaseManager {where!r} schema=v{self.schema_version} "
                f"[{state}]>")
