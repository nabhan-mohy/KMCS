"""
KMCS — Keyless Memory-Corruption Scanner
kmcs.database

Persistence layer for the KMCS platform (Phase 2).

Modules
-------
``models``
    SQLAlchemy ORM tables (targets, authorisations, corpora, campaigns,
    crashes, findings, reproductions, minimizations, reports, regression
    tests, jobs, events, settings, telemetry samples, evidence) plus shared
    column types, defensive-policy row guards, and schema versioning.

``database``
    :class:`DatabaseManager` — thread-safe engine/session lifecycle, WAL +
    foreign-key pragmas, transaction context managers, and CRUD/query APIs
    for every entity, with statistics helpers used by dashboards.

``migrations``
    Real, audited migration engine: bootstrap, forward/backward plans,
    checksummed registry, integrity verification, online backups, and drift
    detection against live SQLite schemas.

Everything here runs fully offline against a local SQLite file. No network,
no credentials, no external services.
"""

from __future__ import annotations

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
    GuardedInsertHooks,
    IsoDateTime,
    JSONText,
    JobRow,
    MinimizationRow,
    ReproductionRow,
    ReportRow,
    RegressionTestRow,
    SCHEMA_VERSION,
    SettingRow,
    SlugList,
    TargetRow,
    TelemetryRow,
    EVIDENCE_TABLE,
    guard_row_policy,
    row_to_dict,
    table_names,
    utc_now,
)
from kmcs.database.database import (
    DatabaseManager,
    DEFAULT_DB_FILENAME,
    DEFAULT_DB_DIRNAME,
    default_database_path,
)
from kmcs.database.migrations import (
    CURRENT_SCHEMA_VERSION,
    MIGRATION_REGISTRY,
    MIN_UPGRADABLE_VERSION,
    REGISTRY_TOP_VERSION,
    ColumnSpec,
    IndexSpec,
    Migration,
    MigrationDirection,
    MigrationPlan,
    MigrationReport,
    MigrationRunner,
    MigrationStatus,
    MigrationStepResult,
    SchemaInfo,
    TableSpec,
    backup_database_file,
    build_bootstrap_migration,
    detect_drift,
    downgrade,
    orm_table_names,
    read_current_version,
    snapshot_schema,
    status as migration_status,
    upgrade,
    verify_integrity,
)

__version__ = "0.2.0"

__all__ = [
    # models
    "AuthorisationRow",
    "Base",
    "CampaignRow",
    "CorpusEntryRow",
    "CorpusRow",
    "CrashRow",
    "EventRow",
    "EvidenceRow",
    "FindingRow",
    "GuardedInsertHooks",
    "IsoDateTime",
    "JSONText",
    "JobRow",
    "MinimizationRow",
    "ReproductionRow",
    "ReportRow",
    "RegressionTestRow",
    "SCHEMA_VERSION",
    "SettingRow",
    "SlugList",
    "TargetRow",
    "TelemetryRow",
    "EVIDENCE_TABLE",
    "guard_row_policy",
    "row_to_dict",
    "table_names",
    "utc_now",
    # manager
    "DatabaseManager",
    "DEFAULT_DB_FILENAME",
    "DEFAULT_DB_DIRNAME",
    "default_database_path",
    # migrations
    "CURRENT_SCHEMA_VERSION",
    "MIGRATION_REGISTRY",
    "MIN_UPGRADABLE_VERSION",
    "REGISTRY_TOP_VERSION",
    "ColumnSpec",
    "IndexSpec",
    "Migration",
    "MigrationDirection",
    "MigrationPlan",
    "MigrationReport",
    "MigrationRunner",
    "MigrationStatus",
    "MigrationStepResult",
    "SchemaInfo",
    "TableSpec",
    "backup_database_file",
    "build_bootstrap_migration",
    "detect_drift",
    "downgrade",
    "orm_table_names",
    "read_current_version",
    "snapshot_schema",
    "migration_status",
    "upgrade",
    "verify_integrity",
]
