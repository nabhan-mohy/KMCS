"""SQLAlchemy ORM layer for KMCS persistence (Phase 2).

This module defines the relational schema used by the local SQLite database:

* :class:`Base` — declarative base with naming conventions that make
  migrations deterministic and portable.
* Table classes: ``targets``, ``authorisations``, ``corpora``,
  ``corpus_entries``, ``campaigns``, ``runs``, ``crashes``, ``findings``,
  ``finding_crashes`` (M2M), ``reproductions``, ``minimizations``,
  ``reports``, ``regression_tests``, ``jobs``, ``events``, ``settings``,
  ``telemetry_samples``.
* Row ⇄ domain conversion helpers on every table
  (``to_domain()`` / ``from_domain(session, obj)``) bridging the rich
  Pydantic-free dataclasses in :mod:`kmcs.core.models` with plain rows.
* JSON payload columns keep full fidelity of nested value objects while
  dedicated scalar columns keep everything important *queryable*
  (status, severity, fingerprints, timestamps, foreign keys).

Design rules honoured here:

1. No secrets/credentials are ever stored — authorisation rows keep only
   who/when/scope metadata (the same contract as ``core.models.Authorisation``).
2. Prohibited capabilities (exploit generation etc.) cannot be represented;
   there is deliberately no column or table for them.  Guarding happens in
   the core layer and again at insert time via :func:`guard_row_policy`.
3. All datetimes are stored as ISO-8601 UTC strings exactly like the core
   models, so round-tripping never re-formats timestamps.
4. Fingerprint digests are content-addressed and indexed UNIQUE where they
   act as deduplication keys.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Table,
    Text,
    UniqueConstraint,
    event,
    func,
    select,
    type_coerce,
)
from sqlalchemy.engine import Engine
from sqlalchemy.event.api import listens_for
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    relationship,
    mapped_column,
    relationship,
)
from sqlalchemy.types import JSON, TypeDecorator

# --------------------------------------------------------------------------- #
# Core model imports (domain objects this ORM maps to/from)
# --------------------------------------------------------------------------- #

from kmcs.core.exceptions import (
    DatabaseError,
    InvalidValueError,
    PolicyViolationError,
    ProhibitedCapabilityError,
)
from kmcs.core import models as cm

__all__ = [
    "Base",
    "NAMING_CONVENTION",
    "TargetRow",
    "AuthorisationRow",
    "CorpusRow",
    "CorpusEntryRow",
    "CampaignRow",
    "CrashRow",
    "FindingRow",
    "finding_crashes",
    "ReproductionRow",
    "MinimizationRow",
    "ReportRow",
    "RegressionTestRow",
    "JobRow",
    "EventRow",
    "SettingRow",
    "TelemetryRow",
    "EVIDENCE_TABLE",
    "EvidenceRow",
    "GuardedInsertHooks",
    "guard_row_policy",
    "row_to_dict",
    "utc_now",
    "SCHEMA_VERSION",
    "TABLE_ORDER",
    "table_names",
]

#: Bumped whenever the ORM schema changes; migrations compare against it.
SCHEMA_VERSION = 1

# --------------------------------------------------------------------------- #
# Helpers shared by all tables
# --------------------------------------------------------------------------- #


def utc_now() -> datetime:
    """Timezone-aware ``now`` in UTC (never naive)."""
    return datetime.now(timezone.utc)


_JSON_SAFE_TYPES = (str, int, float, bool, type(None), list, dict)


def _json_dumps(payload: Any) -> str:
    """Serialise a domain object's ``to_dict()`` output defensively."""
    try:
        return json.dumps(payload, sort_keys=True, default=str,
                          separators=(",", ":"))
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise DatabaseError(f"cannot serialise payload: {exc}",
                            component="database.models") from exc


def _json_loads(text: Any) -> Any:
    if text in (None, ""):
        return {}
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(str(text))
    except (TypeError, ValueError) as exc:
        raise DatabaseError(f"corrupt JSON column: {exc}",
                            component="database.models") from exc


class JSONText(TypeDecorator):
    """Store structured payloads as canonical JSON text.

    SQLAlchemy's built-in ``JSON`` works, but keeping our own decorator lets
    us control serialisation exactly like :mod:`kmcs.core.models` does
    (sorted keys, compact separators, ``default=str`` fallback), which keeps
    fingerprints/digests stable across round trips.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        return _json_dumps(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        return _json_loads(value)


class SlugList(TypeDecorator):
    """List[str] stored as a JSON text array (deduplicated, order-preserving)."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        cleaned: List[str] = []
        seen = set()
        for item in value:
            token = str(item)
            if token and token not in seen:
                seen.add(token)
                cleaned.append(token)
        return _json_dumps(cleaned)

    def process_result_value(self, value: Any, dialect: Any) -> List[str]:
        loaded = _json_loads(value)
        return list(loaded) if isinstance(loaded, list) else []


class IsoDateTime(TypeDecorator):
    """Naive-safe UTC datetimes stored as ISO-8601 text.

    The core models use ISO strings everywhere; matching that avoids any
    drift between the two layers.  Binding accepts ``datetime`` | ``str`` |
    ``None``; results always come back as aware ``datetime`` when parseable.
    """

    impl = String
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            moment = value
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment.astimezone(timezone.utc).isoformat()
        parsed = cm.parse_timestamp(value)
        if parsed is None:
            raise InvalidValueError(f"unparseable timestamp {value!r}",
                                    component="database.models")
        return parsed.isoformat()

    def process_result_value(self, value: Any, dialect: Any) -> Optional[datetime]:
        if value in (None, ""):
            return None
        return cm.parse_timestamp(value)


# --------------------------------------------------------------------------- #
# Governance guard applied to every ORM row before flush
# --------------------------------------------------------------------------- #

#: Capability tokens that must never appear anywhere in persisted state.
PROHIBITED_PERSISTENCE_TOKENS = (
    "exploit_generation",
    "weaponization",
    "shellcode",
    "auto_exploit",
    "privilege_escalation_payload",
    "persistence_mechanism",
    "credential_theft",
    "unauthorized_scan",
    "stealth_mode",
    "security_control_bypass",
)


def _iter_guard_surfaces(obj: Any):
    """Yield ``(label_text, metadata)`` pairs to inspect on *obj*.

    Handles three shapes uniformly:

    * SQLAlchemy ORM rows – every mapped column whose value is a string or a
      list of strings is scanned for prohibited markers, plus ``labels``/
      ``tags``/``metadata_json`` style containers.
    * Plain mappings – all values are considered.
    * Arbitrary objects (duck-typed guards in callers/tests) – any public
      string attribute plus ``labels``/``tags``/``metadata`` attributes.
    """
    if isinstance(obj, Mapping):
        text = " ".join(str(v) for v in obj.values())
        yield text, None
        return

    mapper = None
    try:
        from sqlalchemy.orm import class_mapper
        mapper = class_mapper(type(obj), configure=False)
    except Exception:
        mapper = None

    if mapper is not None:
        texts: List[str] = []
        metadata = None
        for column in mapper.columns:
            key = column.key
            value = getattr(obj, key, None)
            if value is None:
                continue
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, (list, tuple)):
                texts.extend(str(item) for item in value)
            elif isinstance(value, Mapping) and ("meta" in key or "json" in key):
                metadata = value
        for attr in ("labels", "tags"):
            extra = getattr(obj, attr, None)
            if isinstance(extra, (list, tuple)):
                texts.extend(str(item) for item in extra)
        yield " ".join(texts), metadata
        return

    texts = []
    metadata = None
    for attr in ("labels", "tags", "capability", "kind", "name", "notes",
                 "description", "summary"):
        value = getattr(obj, attr, None)
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, (list, tuple)):
            texts.extend(str(item) for item in value)
    for meta_attr in ("metadata_json", "metadata"):
        candidate = getattr(obj, meta_attr, None)
        if isinstance(candidate, Mapping):
            metadata = candidate
            break
    yield " ".join(texts), metadata


def guard_row_policy(obj: Any) -> None:
    """Refuse to persist anything carrying prohibited-capability markers.

    Called from SQLAlchemy ``before_flush``; also safe to call directly on a
    mapping or an arbitrary object as a pre-flight check.  This is defence-in-
    depth: even if some upstream code path produced a hostile label/metadata
    string, it will not silently enter the research database.
    """
    for blob_text, metadata in _iter_guard_surfaces(obj):
        blob = blob_text.lower()
        if metadata is not None:
            try:
                blob += " " + json.dumps(metadata, default=str).lower()
            except (TypeError, ValueError):  # pragma: no cover - defensive
                blob += " " + str(metadata).lower()
        table = getattr(type(obj), "__tablename__", "?")
        for token in PROHIBITED_PERSISTENCE_TOKENS:
            if token in blob:
                raise ProhibitedCapabilityError(
                    f"refusing to persist row {type(obj).__name__}: "
                    f"prohibited capability marker '{token}'",
                    component="database.models",
                    context={"table": table},
                )


class GuardedInsertHooks:
    """Namespace documenting the automatic guards wired onto Base."""

    @staticmethod
    def enforce_before_write(mapper: Any, connection: Any, target: Any) -> None:
        guard_row_policy(target)


# --------------------------------------------------------------------------- #
# Declarative base & naming convention
# --------------------------------------------------------------------------- #

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every KMCS table."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk_cols = [c.name for c in type(self).__mapper__.primary_key]
        values = ", ".join(f"{c}={getattr(self, c, None)!r}" for c in pk_cols)
        return f"<{type(self).__name__} {values}>"

    # -- generic utilities ------------------------------------------------------
    def to_row_dict(self, *, include: Optional[Sequence[str]] = None,
                    exclude: Sequence[str] = ()) -> Dict[str, Any]:
        mapper = type(self).__mapper__
        out: Dict[str, Any] = {}
        for column in mapper.columns:
            name = column.key
            if include is not None and name not in include:
                continue
            if name in exclude:
                continue
            value = getattr(self, name, None)
            if isinstance(value, datetime):
                value = value.isoformat()
            out[name] = value
        return out


def row_to_dict(row: Base, **kwargs: Any) -> Dict[str, Any]:
    """Module-level convenience wrapper around :meth:`Base.to_row_dict`."""
    return row.to_row_dict(**kwargs)


# Wire governance + integrity hooks once per-mapper at configure time.
_CONFIGURED_HOOKS = False


def _install_hooks() -> None:
    global _CONFIGURED_HOOKS
    if _CONFIGURED_HOOKS:
        return
    _CONFIGURED_HOOKS = True

    @event.listens_for(Base, "mapper_configured", propagate=True)
    def _on_mapper_configured(mapper: Any, class_: Any) -> None:  # pragma: no cover
        pass

    @event.listens_for(Session, "before_flush")
    def _before_flush(session: Session, flush_context: Any,
                      instances: Any) -> None:
        dirty: List[Any] = []
        dirty.extend(list(session.new))
        dirty.extend(list(session.dirty))
        for obj in dirty:
            if isinstance(obj, Base):
                guard_row_policy(obj)


# --------------------------------------------------------------------------- #
# targets & authorisation
# --------------------------------------------------------------------------- #


class TargetRow(Base):
    """Persisted fuzzing target (one authorised C/C++ artefact)."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    binary_path: Mapped[str] = mapped_column(String(1024), default="")
    source_root: Mapped[str] = mapped_column(String(1024), default="")
    kind: Mapped[str] = mapped_column(String(32), default="binary", index=True)
    language: Mapped[str] = mapped_column(String(32), default="unknown")
    architecture: Mapped[str] = mapped_column(String(32), default="unknown")
    operating_system: Mapped[str] = mapped_column(String(32), default="unknown")
    upstream_project: Mapped[str] = mapped_column(String(255), default="")
    upstream_url: Mapped[str] = mapped_column(String(1024), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    instrumented: Mapped[bool] = mapped_column(Boolean, default=False)
    instrumentation: Mapped[str] = mapped_column(String(32), default="none")
    sanitizers_enabled: Mapped[List[str]] = mapped_column(SlugList, default=list)
    tags: Mapped[List[str]] = mapped_column(SlugList, default=list)
    build_recipe_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    harness_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    authorisation_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("authorisations.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 onupdate=utc_now)

    authorisation: Mapped[Optional["AuthorisationRow"]] = relationship(
        "AuthorisationRow", back_populates="targets", foreign_keys=[authorisation_id])
    campaigns: Mapped[List["CampaignRow"]] = relationship(
        "CampaignRow", back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_targets_name_kind", "name", "kind"),
    )

    # -- conversions ------------------------------------------------------------
    @classmethod
    def from_domain(cls, target: cm.Target,
                    authorisation_row: Optional["AuthorisationRow"] = None
                    ) -> "TargetRow":
        if not isinstance(target, cm.Target):
            raise InvalidValueError(
                f"expected core Target, got {type(target).__name__}",
                component="database.models")
        row = cls(
            id=target.id,
            name=target.name,
            binary_path=target.binary_path,
            source_root=target.source_root,
            kind=target.kind,
            language=target.language,
            architecture=target.architecture,
            operating_system=target.operating_system,
            upstream_project=target.upstream_project,
            upstream_url=target.upstream_url,
            version=target.version,
            instrumented=bool(target.instrumented),
            instrumentation=target.instrumentation,
            sanitizers_enabled=list(target.sanitizers_enabled),
            tags=list(target.tags),
            build_recipe_json=target.build_recipe.to_dict(),
            harness_json=target.harness.to_dict(),
            metadata_json=dict(target.metadata),
            authorisation_id=(authorisation_row.id if authorisation_row
                              else (target.authorisation.id
                                    if target.authorisation else None)),
        )
        return row

    def to_domain(self, authorisation: Optional[cm.Authorisation] = None
                  ) -> cm.Target:
        payload = {
            "id": self.id, "name": self.name, "binary_path": self.binary_path,
            "source_root": self.source_root, "kind": self.kind,
            "language": self.language, "architecture": self.architecture,
            "operating_system": self.operating_system,
            "upstream_project": self.upstream_project,
            "upstream_url": self.upstream_url, "version": self.version,
            "instrumented": self.instrumented, "instrumentation": self.instrumentation,
            "sanitizers_enabled": list(self.sanitizers_enabled),
            "tags": list(self.tags), "metadata": dict(self.metadata_json or {}),
            "created_at": cm.utc_string(self.created_at),
            "updated_at": cm.utc_string(self.updated_at),
        }
        recipe = self.build_recipe_json or {}
        harness = self.harness_json or {}
        target = cm.Target(
            build_recipe=(cm.BuildRecipe.from_dict(recipe)
                          if isinstance(recipe, Mapping) else cm.BuildRecipe()),
            harness=(cm.HarnessSpec.from_dict(harness)
                     if isinstance(harness, Mapping) else cm.HarnessSpec()),
            authorisation=authorisation,
            **payload,
        )
        return target


class AuthorisationRow(Base):
    """Written permission record; strictly who/when/scope — never secrets."""

    __tablename__ = "authorisations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    granted_by: Mapped[str] = mapped_column(String(255), default="")
    granted_to: Mapped[str] = mapped_column(String(255), default="")
    document_ref: Mapped[str] = mapped_column(String(512), default="")
    scope_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    operations: Mapped[List[str]] = mapped_column(SlugList, default=list)
    capabilities: Mapped[List[str]] = mapped_column(SlugList, default=list)
    issued_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True,
                                                           index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    revoked_by: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)

    targets: Mapped[List[TargetRow]] = relationship(
        "TargetRow", back_populates="authorisation")

    __table_args__ = (
        CheckConstraint("revoked = 0 OR revoked = 1", name="bool_revoked"),
    )

    @classmethod
    def from_domain(cls, auth: cm.Authorisation) -> "AuthorisationRow":
        if not isinstance(auth, cm.Authorisation):
            raise InvalidValueError(
                f"expected core Authorisation, got {type(auth).__name__}",
                component="database.models")
        payload = auth.to_dict()
        scope = payload.get("scope") or {}
        return cls(
            id=auth.id,
            granted_by=getattr(auth, "granted_by", ""),
            granted_to=getattr(auth, "granted_to", ""),
            document_ref=getattr(auth, "document_ref", ""),
            scope_json=dict(scope) if isinstance(scope, Mapping) else {},
            operations=list(getattr(auth, "operations", []) or []),
            capabilities=list(getattr(auth, "capabilities", []) or []),
            issued_at=cm.parse_timestamp(getattr(auth, "issued_at", None)),
            expires_at=cm.parse_timestamp(getattr(auth, "expires_at", None)),
            revoked=bool(getattr(auth, "revoked", False)),
            revoked_at=cm.parse_timestamp(getattr(auth, "revoked_at", None)),
            revoked_by=getattr(auth, "revoked_by", "") or "",
            notes=getattr(auth, "notes", "") or "",
        )

    def to_domain(self) -> cm.Authorisation:
        payload = {
            "id": self.id,
            "granted_by": self.granted_by,
            "granted_to": self.granted_to,
            "document_ref": self.document_ref,
            "operations": list(self.operations),
            "capabilities": list(self.capabilities),
            "issued_at": cm.utc_string(self.issued_at),
            "expires_at": cm.utc_string(self.expires_at),
            "revoked": bool(self.revoked),
            "revoked_at": cm.utc_string(self.revoked_at),
            "revoked_by": self.revoked_by,
            "notes": self.notes,
            "scope": dict(self.scope_json or {}),
        }
        return cm.Authorisation.from_dict(payload)


# --------------------------------------------------------------------------- #
# corpus
# --------------------------------------------------------------------------- #


class CorpusRow(Base):
    """A named collection of seed inputs."""

    __tablename__ = "corpora"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    target_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    format_hint: Mapped[str] = mapped_column(String(64), default="")
    tags: Mapped[List[str]] = mapped_column(SlugList, default=list)
    entry_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 onupdate=utc_now)

    entries: Mapped[List["CorpusEntryRow"]] = relationship(
        "CorpusEntryRow", back_populates="corpus", cascade="all, delete-orphan",
        order_by="CorpusEntryRow.added_at")

    __table_args__ = (
        Index("ix_corpora_target_name", "target_id", "name"),
    )

    @classmethod
    def from_domain(cls, corpus: cm.Corpus) -> "CorpusRow":
        stats = corpus.stats() if hasattr(corpus, "stats") else None
        row = cls(
            id=corpus.id,
            name=getattr(corpus, "name", "") or corpus.id,
            target_id=getattr(corpus, "target_id", None),
            description=getattr(corpus, "description", "") or "",
            format_hint=getattr(corpus, "format_hint", "") or "",
            tags=list(getattr(corpus, "tags", []) or []),
            entry_count=len(getattr(corpus, "entries", []) or []),
            total_bytes=sum(int(getattr(e, "size_bytes", 0) or 0)
                            for e in (getattr(corpus, "entries", []) or [])),
        )
        if stats is not None and isinstance(stats, cm.CorpusStats):
            row.entry_count = int(stats.count or row.entry_count)
            row.total_bytes = int(stats.total_bytes or row.total_bytes)
        return row

    def summary_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "target_id": self.target_id,
            "entry_count": self.entry_count, "total_bytes": self.total_bytes,
            "tags": list(self.tags),
            "created_at": cm.utc_string(self.created_at),
            "updated_at": cm.utc_string(self.updated_at),
        }


class CorpusEntryRow(Base):
    """One seed file inside a corpus (content-addressed by hash)."""

    __tablename__ = "corpus_entries"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    corpus_id: Mapped[str] = mapped_column(
        ForeignKey("corpora.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    content_hash: Mapped[str] = mapped_column(String(80), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    input_class: Mapped[str] = mapped_column(String(32), default="unknown")
    label: Mapped[str] = mapped_column(String(255), default="")
    origin: Mapped[str] = mapped_column(String(64), default="manual")
    tags: Mapped[List[str]] = mapped_column(SlugList, default=list)
    added_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime,
                                                             nullable=True)

    corpus: Mapped[CorpusRow] = relationship("CorpusRow", back_populates="entries")

    __table_args__ = (
        UniqueConstraint("corpus_id", "content_hash",
                         name="uq_corpus_entry_hash"),
        Index("ix_corpus_entries_class", "corpus_id", "input_class"),
    )

    @classmethod
    def from_domain(cls, entry: cm.CorpusEntry, corpus_id: str) -> "CorpusEntryRow":
        return cls(
            id=entry.id,
            corpus_id=corpus_id,
            path=entry.path,
            content_hash=entry.content_hash,
            size_bytes=int(entry.size_bytes),
            input_class=str(entry.input_class),
            label=entry.label,
            origin=entry.origin,
            tags=list(entry.tags),
            added_at=cm.parse_timestamp(entry.added_at) or utc_now(),
            last_seen_at=cm.parse_timestamp(entry.last_seen_at),
        )

    def to_domain(self) -> cm.CorpusEntry:
        return cm.CorpusEntry(
            id=self.id, path=self.path, content_hash=self.content_hash,
            size_bytes=self.size_bytes, input_class=self.input_class,
            label=self.label, origin=self.origin, tags=list(self.tags),
            added_at=cm.utc_string(self.added_at),
            last_seen_at=cm.utc_string(self.last_seen_at),
        )


# --------------------------------------------------------------------------- #
# campaigns
# --------------------------------------------------------------------------- #


class CampaignRow(Base):
    """A managed fuzzing session against one authorised target."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="RESTRICT"), index=True)
    engine: Mapped[str] = mapped_column(String(32), default="afl++", index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    worker_count: Mapped[int] = mapped_column(Integer, default=1)
    max_runtime_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    max_input_bytes: Mapped[int] = mapped_column(Integer, default=1 << 20)
    sanitizers: Mapped[List[str]] = mapped_column(SlugList, default=list)
    corpus_ids: Mapped[List[str]] = mapped_column(SlugList, default=list)
    crash_dir: Mapped[str] = mapped_column(String(1024), default="")
    work_dir: Mapped[str] = mapped_column(String(1024), default="")
    log_path: Mapped[str] = mapped_column(String(1024), default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[List[str]] = mapped_column(SlugList, default=list)
    engine_session_id: Mapped[Optional[str]] = mapped_column(String(128),
                                                             nullable=True)
    metrics_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)
    started_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)

    target: Mapped[TargetRow] = relationship("TargetRow", back_populates="campaigns")
    crashes: Mapped[List["CrashRow"]] = relationship(
        "CrashRow", back_populates="campaign", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_campaigns_status_created", "status", "created_at"),
        CheckConstraint("worker_count >= 1", name="workers_positive"),
    )

    @classmethod
    def from_domain(cls, campaign: cm.Campaign) -> "CampaignRow":
        return cls(
            id=campaign.id,
            name=campaign.name,
            target_id=campaign.target_id,
            engine=campaign.engine,
            status=campaign.status,
            worker_count=int(campaign.worker_count),
            max_runtime_seconds=(float(campaign.max_runtime_seconds)
                                 if campaign.max_runtime_seconds else None),
            max_input_bytes=int(campaign.max_input_bytes),
            sanitizers=list(campaign.sanitizers),
            corpus_ids=list(campaign.corpus_ids),
            crash_dir=campaign.crash_dir,
            work_dir=campaign.work_dir,
            log_path=campaign.log_path,
            owner=campaign.owner,
            notes=campaign.notes,
            labels=list(campaign.labels),
            engine_session_id=campaign.engine_session_id,
            metrics_json=campaign.metrics.to_dict(),
            created_at=cm.parse_timestamp(campaign.created_at) or utc_now(),
            started_at=cm.parse_timestamp(campaign.started_at),
            finished_at=cm.parse_timestamp(campaign.finished_at),
        )

    def to_domain(self) -> cm.Campaign:
        metrics_payload = dict(self.metrics_json or {})
        known = {f.name for f in cm.fields(cm.CampaignMetrics)} \
            if hasattr(cm, "fields") else set()
        kwargs = {k: v for k, v in metrics_payload.items() if not known or k in known}
        campaign = cm.Campaign(
            id=self.id, name=self.name, target_id=self.target_id,
            engine=self.engine, status=self.status,
            worker_count=self.worker_count,
            max_runtime_seconds=self.max_runtime_seconds,
            max_input_bytes=self.max_input_bytes,
            sanitizers=list(self.sanitizers),
            corpus_ids=list(self.corpus_ids),
            crash_dir=self.crash_dir, work_dir=self.work_dir,
            log_path=self.log_path, owner=self.owner, notes=self.notes,
            labels=list(self.labels), engine_session_id=self.engine_session_id,
            created_at=cm.utc_string(self.created_at),
            started_at=cm.utc_string(self.started_at),
            finished_at=cm.utc_string(self.finished_at),
        )
        try:
            for key, value in kwargs.items():
                setattr(campaign.metrics, key, value)
        except Exception:
            pass
        return campaign


# --------------------------------------------------------------------------- #
# crashes
# --------------------------------------------------------------------------- #


class CrashRow(Base):
    """Observed crash instance + analysis state (fingerprints indexed)."""

    __tablename__ = "crashes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=True, index=True)
    target_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
    target_name: Mapped[str] = mapped_column(String(255), default="")
    executable: Mapped[str] = mapped_column(String(1024), default="")
    engine: Mapped[str] = mapped_column(String(32), default="")
    sanitizer: Mapped[str] = mapped_column(String(32), default="none", index=True)
    crash_class: Mapped[str] = mapped_column(String(48), default="unknown", index=True)
    state: Mapped[str] = mapped_column(String(32), default="new", index=True)
    severity: Mapped[str] = mapped_column(String(24), default="moderate", index=True)
    confidence: Mapped[str] = mapped_column(String(24), default="unknown")
    input_path: Mapped[str] = mapped_column(String(1024), default="")
    input_hash: Mapped[str] = mapped_column(String(80), default="", index=True)
    input_size: Mapped[int] = mapped_column(Integer, default=0)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    runtime_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    fingerprint_digest: Mapped[str] = mapped_column(String(80), default="",
                                                    index=True)
    duplicate_of: Mapped[Optional[str]] = mapped_column(
        ForeignKey("crashes.id", ondelete="SET NULL"), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    signal_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    memory_access_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    location_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    stack_trace_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    sanitizer_report_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    fingerprint_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    reproducer_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    minimized_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    triaged_by: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[List[str]] = mapped_column(SlugList, default=list)
    raw_log_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                    index=True)
    last_seen_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)

    campaign: Mapped[Optional[CampaignRow]] = relationship(
        "CampaignRow", back_populates="crashes")
    duplicates: Mapped[List["CrashRow"]] = relationship(
        "CrashRow", remote_side=[id], backref="canonical")

    __table_args__ = (
        Index("ix_crashes_campaign_state", "campaign_id", "state"),
        Index("ix_crashes_fingerprint_dup", "fingerprint_digest", "duplicate_of"),
        CheckConstraint("occurrence_count >= 1", name="occurrences_positive"),
    )

    @classmethod
    def from_domain(cls, crash: cm.Crash) -> "CrashRow":
        fp = crash.fingerprint
        return cls(
            id=crash.id,
            campaign_id=crash.campaign_id,
            target_id=crash.target_id,
            target_name=crash.target_name,
            executable=crash.executable,
            engine=crash.engine,
            sanitizer=crash.sanitizer,
            crash_class=crash.crash_class,
            state=crash.state,
            severity=crash.severity,
            confidence=crash.confidence,
            input_path=crash.input_path,
            input_hash=crash.input_hash,
            input_size=int(crash.input_size),
            exit_code=crash.exit_code,
            runtime_ms=crash.runtime_ms,
            fingerprint_digest=(fp.digest if fp else crash.fingerprint_digest),
            duplicate_of=crash.duplicate_of,
            occurrence_count=int(crash.occurrence_count),
            signal_json=crash.signal.to_dict() if crash.signal else {},
            memory_access_json=(crash.memory_access.to_dict()
                                if crash.memory_access else {}),
            location_json=crash.location.to_dict(),
            stack_trace_json=crash.stack_trace.to_dict(),
            sanitizer_report_json=(crash.sanitizer_report.to_dict()
                                   if crash.sanitizer_report else {}),
            fingerprint_json=fp.to_dict() if fp else {},
            reproducer_path=crash.reproducer_path,
            minimized_path=crash.minimized_path,
            finding_id=crash.finding_id,
            triaged_by=crash.triaged_by,
            notes=crash.notes,
            labels=list(crash.labels),
            raw_log_path=crash.raw_log_path,
            first_seen_at=cm.parse_timestamp(crash.first_seen_at) or utc_now(),
            last_seen_at=cm.parse_timestamp(crash.last_seen_at) or utc_now(),
        )

    def to_domain(self) -> cm.Crash:
        payload: Dict[str, Any] = {
            "id": self.id, "campaign_id": self.campaign_id,
            "target_id": self.target_id, "target_name": self.target_name,
            "executable": self.executable, "engine": self.engine,
            "sanitizer": self.sanitizer, "crash_class": self.crash_class,
            "state": self.state, "severity": self.severity,
            "confidence": self.confidence, "input_path": self.input_path,
            "input_hash": self.input_hash, "input_size": self.input_size,
            "exit_code": self.exit_code, "runtime_ms": self.runtime_ms,
            "duplicate_of": self.duplicate_of,
            "occurrence_count": self.occurrence_count,
            "reproducer_path": self.reproducer_path,
            "minimized_path": self.minimized_path,
            "finding_id": self.finding_id, "triaged_by": self.triaged_by,
            "notes": self.notes, "labels": list(self.labels),
            "raw_log_path": self.raw_log_path,
            "first_seen_at": cm.utc_string(self.first_seen_at),
            "last_seen_at": cm.utc_string(self.last_seen_at),
        }
        if self.signal_json:
            payload["signal"] = dict(self.signal_json)
        if self.memory_access_json:
            payload["memory_access"] = dict(self.memory_access_json)
        if self.location_json:
            payload["location"] = dict(self.location_json)
        if self.stack_trace_json:
            payload["stack_trace"] = dict(self.stack_trace_json)
        if self.sanitizer_report_json:
            payload["sanitizer_report"] = dict(self.sanitizer_report_json)
        if self.fingerprint_json:
            payload["fingerprint"] = dict(self.fingerprint_json)
        return cm.Crash.from_dict(payload)


# --------------------------------------------------------------------------- #
# findings (+ association table for M2M with crashes)
# --------------------------------------------------------------------------- #




class FindingRow(Base):
    """Structured security finding distilled from one or more crashes."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    target_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    target_name: Mapped[str] = mapped_column(String(255), default="")
    campaign_ids: Mapped[List[str]] = mapped_column(SlugList, default=list)
    canonical_crash_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("crashes.id", ondelete="SET NULL"), nullable=True)
    crash_class: Mapped[str] = mapped_column(String(48), default="unknown",
                                             index=True)
    severity: Mapped[str] = mapped_column(String(24), default="moderate", index=True)
    confidence: Mapped[str] = mapped_column(String(24), default="medium")
    state: Mapped[str] = mapped_column(String(32), default="candidate", index=True)
    fingerprint_digest: Mapped[str] = mapped_column(String(80), default="",
                                                    index=True)
    location_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    stack_signature: Mapped[str] = mapped_column(Text, default="")
    root_cause_hints_json: Mapped[List[Any]] = mapped_column(JSONText, default=list)
    trigger_conditions: Mapped[List[str]] = mapped_column(SlugList, default=list)
    affected_versions: Mapped[List[str]] = mapped_column(SlugList, default=list)
    fixed_in: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    evidence_json: Mapped[List[Any]] = mapped_column(JSONText, default=list)
    references_json: Mapped[List[str]] = mapped_column(SlugList, default=list)
    labels: Mapped[List[str]] = mapped_column(SlugList, default=list)
    assignee: Mapped[str] = mapped_column(String(255), default="")
    analyst: Mapped[str] = mapped_column(String(255), default="")
    disclosure_notes: Mapped[str] = mapped_column(Text, default="")
    cvss_vector_hint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                    index=True)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    reported_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 onupdate=utc_now)

    __table_args__ = (
        Index("ix_findings_severity_state", "severity", "state"),
    )

    @classmethod
    def from_domain(cls, finding: cm.Finding) -> "FindingRow":
        fp = finding.fingerprint
        return cls(
            id=finding.id,
            title=finding.title,
            summary=finding.summary,
            description=finding.description,
            target_id=finding.target_id,
            target_name=finding.target_name,
            campaign_ids=list(finding.campaign_ids),
            canonical_crash_id=finding.canonical_crash_id,
            crash_class=finding.crash_class,
            severity=finding.severity,
            confidence=finding.confidence,
            state=finding.state,
            fingerprint_digest=(fp.digest if fp else ""),
            location_json=finding.location.to_dict(),
            stack_signature=finding.stack_signature,
            root_cause_hints_json=[h.to_dict() if hasattr(h, "to_dict") else h
                                   for h in finding.root_cause_hints],
            trigger_conditions=list(finding.trigger_conditions),
            affected_versions=list(finding.affected_versions),
            fixed_in=finding.fixed_in,
            evidence_json=[e.to_dict() if hasattr(e, "to_dict") else e
                           for e in finding.evidence],
            references_json=list(finding.references),
            labels=list(finding.labels),
            assignee=finding.assignee,
            analyst=finding.analyst,
            disclosure_notes=finding.disclosure_notes,
            cvss_vector_hint=finding.cvss_vector_hint,
            discovered_at=cm.parse_timestamp(finding.discovered_at) or utc_now(),
            confirmed_at=cm.parse_timestamp(finding.confirmed_at),
            reported_at=cm.parse_timestamp(finding.reported_at),
            closed_at=cm.parse_timestamp(finding.closed_at),
            updated_at=cm.parse_timestamp(finding.updated_at) or utc_now(),
        )

    def to_domain(self, crash_ids: Optional[Sequence[str]] = None
                  ) -> cm.Finding:
        finding = cm.Finding(
            id=self.id, title=self.title, summary=self.summary,
            description=self.description, target_id=self.target_id,
            target_name=self.target_name,
            campaign_ids=list(self.campaign_ids),
            crash_ids=list(crash_ids or []),
            canonical_crash_id=self.canonical_crash_id,
            crash_class=self.crash_class, severity=self.severity,
            confidence=self.confidence, state=self.state,
            stack_signature=self.stack_signature,
            trigger_conditions=list(self.trigger_conditions),
            affected_versions=list(self.affected_versions),
            fixed_in=self.fixed_in,
            references=list(self.references_json),
            labels=list(self.labels),
            assignee=self.assignee, analyst=self.analyst,
            disclosure_notes=self.disclosure_notes,
            cvss_vector_hint=self.cvss_vector_hint,
            discovered_at=cm.utc_string(self.discovered_at),
            confirmed_at=cm.utc_string(self.confirmed_at),
            reported_at=cm.utc_string(self.reported_at),
            closed_at=cm.utc_string(self.closed_at),
            updated_at=cm.utc_string(self.updated_at),
        )
        if self.fingerprint_digest:
            finding.fingerprint = cm.Fingerprint.from_dict({
                "digest": self.fingerprint_digest,
                "components": self.location_json.get("_fp_components", {})
                if isinstance(self.location_json, Mapping) else {},
            })
        return finding


# Association table linking findings <-> crashes (many-to-many).




finding_crashes = Table(
    "finding_crashes",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"),
           primary_key=True),
    Column("crash_id", ForeignKey("crashes.id", ondelete="CASCADE"),
           primary_key=True),
    Column("role", String(32), default="member"),  # member|canonical|related
    Index("ix_finding_crashes_crash", "crash_id"),
)

# Convenience query helper exposed on FindingRow (declared via string
# reference so it resolves after mappers configure).
def _finding_linked_crashes(self: "FindingRow") -> List[CrashRow]:
    session = Session.object_session(self)
    if session is None:
        return []
    rows = session.execute(
        select(CrashRow).join(finding_crashes, finding_crashes.c.crash_id == CrashRow.id)
        .where(finding_crashes.c.finding_id == self.id)
        .order_by(CrashRow.first_seen_at)
    ).scalars().all()
    return list(rows)


FindingRow.linked_crashes = property(_finding_linked_crashes)


# --------------------------------------------------------------------------- #
# reproduction / minimization / regression / reports
# --------------------------------------------------------------------------- #


class ReproductionRow(Base):
    """Outcome of an attempt to reproduce a crash on the current build."""

    __tablename__ = "reproductions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    crash_id: Mapped[str] = mapped_column(
        ForeignKey("crashes.id", ondelete="CASCADE"), index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=1)
    successful_attempts: Mapped[int] = mapped_column(Integer, default=0)
    reproducibility_rate: Mapped[float] = mapped_column(Float, default=0.0)
    exit_codes_json: Mapped[List[int]] = mapped_column(SlugList, default=list)
    signals_json: Mapped[List[Any]] = mapped_column(JSONText, default=list)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    environment_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    performed_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                   index=True)
    performed_by: Mapped[str] = mapped_column(String(255), default="")

    __table_args__ = (
        CheckConstraint("attempts >= 0", name="attempts_nonneg"),
        CheckConstraint("successful_attempts <= attempts",
                        name="success_lte_attempts"),
    )

    @classmethod
    def from_domain(cls, result: cm.ReproductionResult) -> "ReproductionRow":
        payload = result.to_dict() if hasattr(result, "to_dict") else {}
        return cls(
            id=payload.get("id") or cm.generate_prefixed_id("repro"),
            crash_id=payload.get("crash_id", ""),
            campaign_id=payload.get("campaign_id"),
            outcome=str(payload.get("outcome", "unknown")),
            attempts=int(payload.get("attempts", 1) or 1),
            successful_attempts=int(payload.get("successful_attempts", 0) or 0),
            reproducibility_rate=float(payload.get("reproducibility_rate", 0.0) or 0.0),
            exit_codes_json=list(payload.get("exit_codes", []) or []),
            signals_json=list(payload.get("signals", []) or []),
            duration_seconds=float(payload.get("duration_seconds", 0.0) or 0.0),
            environment_json=dict(payload.get("environment", {}) or {}),
            notes=str(payload.get("notes", "") or ""),
            performed_at=cm.parse_timestamp(payload.get("performed_at")) or utc_now(),
            performed_by=str(payload.get("performed_by", "") or ""),
        )


class MinimizationRow(Base):
    """Result of test-case minimisation for a crash input."""

    __tablename__ = "minimizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    crash_id: Mapped[str] = mapped_column(
        ForeignKey("crashes.id", ondelete="CASCADE"), index=True)
    original_path: Mapped[str] = mapped_column(String(1024), default="")
    original_size: Mapped[int] = mapped_column(Integer, default=0)
    minimized_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    minimized_size: Mapped[int] = mapped_column(Integer, default=0)
    reduction_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    iterations: Mapped[int] = mapped_column(Integer, default=0)
    strategy: Mapped[str] = mapped_column(String(64), default="ddmin")
    still_crashes: Mapped[bool] = mapped_column(Boolean, default=False)
    tool: Mapped[str] = mapped_column(String(64), default="")
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str] = mapped_column(Text, default="")
    performed_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)

    @classmethod
    def from_domain(cls, result: cm.MinimizationResult) -> "MinimizationRow":
        payload = result.to_dict() if hasattr(result, "to_dict") else {}
        return cls(
            id=payload.get("id") or cm.generate_prefixed_id("min"),
            crash_id=payload.get("crash_id", ""),
            original_path=str(payload.get("original_path", "")),
            original_size=int(payload.get("original_size", 0) or 0),
            minimized_path=payload.get("minimized_path"),
            minimized_size=int(payload.get("minimized_size", 0) or 0),
            reduction_ratio=float(payload.get("reduction_ratio", 0.0) or 0.0),
            iterations=int(payload.get("iterations", 0) or 0),
            strategy=str(payload.get("strategy", "ddmin")),
            still_crashes=bool(payload.get("still_crashes", False)),
            tool=str(payload.get("tool", "") or ""),
            duration_seconds=float(payload.get("duration_seconds", 0.0) or 0.0),
            notes=str(payload.get("notes", "") or ""),
            performed_at=cm.parse_timestamp(payload.get("performed_at")) or utc_now(),
        )


class ReportRow(Base):
    """Generated report artifact metadata (files live on disk; DB tracks them)."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    fmt: Mapped[str] = mapped_column(String(16), default="markdown", index=True)
    path: Mapped[str] = mapped_column(String(1024), default="")
    content_hash: Mapped[str] = mapped_column(String(80), default="", index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    generator: Mapped[str] = mapped_column(String(128), default="kmcs")
    options_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 index=True)

    __table_args__ = (
        UniqueConstraint("finding_id", "fmt", "content_hash",
                         name="uq_report_identity"),
    )


class RegressionTestRow(Base):
    """A pinned reproducer registered as a regression test."""

    __tablename__ = "regression_tests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    crash_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("crashes.id", ondelete="SET NULL"), nullable=True, index=True)
    target_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    input_path: Mapped[str] = mapped_column(String(1024), default="")
    input_hash: Mapped[str] = mapped_column(String(80), default="", index=True)
    expected_signal: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(IsoDateTime,
                                                            nullable=True)
    last_outcome: Mapped[str] = mapped_column(String(32), default="never-run")
    pass_count: Mapped[int] = mapped_column(Integer, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)

    @classmethod
    def from_domain(cls, test: cm.RegressionTest) -> "RegressionTestRow":
        payload = test.to_dict() if hasattr(test, "to_dict") else {}
        return cls(
            id=payload.get("id") or cm.generate_prefixed_id("reg"),
            finding_id=payload.get("finding_id"),
            crash_id=payload.get("crash_id"),
            target_id=str(payload.get("target_id", "")),
            name=str(payload.get("name", "")),
            input_path=str(payload.get("input_path", "")),
            input_hash=str(payload.get("input_hash", "")),
            expected_signal=payload.get("expected_signal"),
            enabled=bool(payload.get("enabled", True)),
            notes=str(payload.get("notes", "") or ""),
        )


# --------------------------------------------------------------------------- #
# jobs & events (telemetry persistence mirrors of core engines)
# --------------------------------------------------------------------------- #


class JobRow(Base):
    """Durable mirror of a core job definition + latest state."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(48), default="custom", index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    state: Mapped[str] = mapped_column(String(32), default="created", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    depends_on_json: Mapped[List[str]] = mapped_column(SlugList, default=list)
    tags: Mapped[List[str]] = mapped_column(SlugList, default=list)
    payload_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")
    campaign_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 onupdate=utc_now)


class EventRow(Base):
    """Append-only audit trail of bus events (optional persistence sink)."""

    __tablename__ = "events"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    topic: Mapped[str] = mapped_column(String(255), index=True)
    etype: Mapped[str] = mapped_column(String(48), default="", index=True)
    source: Mapped[str] = mapped_column(String(128), default="")
    correlation_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    payload_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                  index=True)

    __table_args__ = (
        Index("ix_events_topic_time", "topic", "occurred_at"),
    )


class SettingRow(Base):
    """Simple durable key/value store for UI/engine settings."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value_json: Mapped[Any] = mapped_column(JSONText, default=None)
    category: Mapped[str] = mapped_column(String(64), default="general",
                                          index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                                 onupdate=utc_now)


class TelemetryRow(Base):
    """Periodic health snapshots for live dashboards."""

    __tablename__ = "telemetry_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), index=True)
    sample_json: Mapped[Dict[str, Any]] = mapped_column(JSONText, default=dict)
    taken_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now,
                                               index=True)

    __table_args__ = (
        Index("ix_telemetry_campaign_time", "campaign_id", "taken_at"),
    )


class EvidenceRow(Base):
    """Standalone evidence artifacts attached to findings.

    ``subject`` names the entity the artifact belongs to (a finding, crash or
    campaign id); ``capability`` optionally records which defensive capability
    produced it — a free-text field that the row guard actively polices, so a
    value such as ``shellcode_generation`` can never be persisted.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(128), default="", index=True)
    capability: Mapped[str] = mapped_column(String(128), default="")
    kind: Mapped[str] = mapped_column(String(48), default="artifact")
    path: Mapped[str] = mapped_column(String(1024), default="")
    content_hash: Mapped[str] = mapped_column(String(80), default="", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    collected_at: Mapped[datetime] = mapped_column(IsoDateTime, default=utc_now)


EVIDENCE_TABLE = EvidenceRow.__tablename__


# --------------------------------------------------------------------------- #
# Deterministic ordering for create_all / migrations
# --------------------------------------------------------------------------- #

TABLE_ORDER: Tuple[str, ...] = (
    "authorisations",
    "targets",
    "corpora",
    "corpus_entries",
    "campaigns",
    "findings",
    "crashes",
    "finding_crashes",
    "reproductions",
    "minimizations",
    "reports",
    "regression_tests",
    "jobs",
    "events",
    "settings",
    "telemetry_samples",
    "evidence",
)


def table_names() -> List[str]:
    """All mapped table names in dependency-respecting order."""
    return list(TABLE_ORDER)


# Install governance hooks now that all mappers exist.
_install_hooks()
