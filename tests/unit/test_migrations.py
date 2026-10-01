"""Unit tests for kmcs.database.migrations (Phase 2)."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text

from kmcs.core.exceptions import MigrationError, SchemaVersionError
from kmcs.database.migrations import (
    CURRENT_SCHEMA_VERSION,
    MIGRATION_REGISTRY,
    REGISTRY_TOP_VERSION,
    ColumnSpec,
    IndexSpec,
    Migration,
    MigrationDirection,
    MigrationRunner,
    MigrationStatus,
    TableSpec,
    backup_database_file,
    build_bootstrap_migration,
    detect_drift,
    downgrade,
    orm_table_names,
    read_current_version,
    schema_migrations_ddl,
    snapshot_schema,
    status as migration_status,
    upgrade,
    verify_integrity,
)


@pytest.fixture()
def engine(tmp_path):
    path = str(tmp_path / "mig.db")
    eng = create_engine(f"sqlite:///{path}")
    yield eng, path
    eng.dispose()


# --------------------------------------------------------------------- #
# declarative spec validation
# --------------------------------------------------------------------- #


def test_column_spec_rejects_bad_identifier():
    with pytest.raises(MigrationError):
        ColumnSpec(name="bad;name", sql_type="TEXT")


def test_column_spec_requires_default_for_not_null():
    with pytest.raises(MigrationError):
        ColumnSpec(name="x", sql_type="INTEGER", nullable=False)
    col = ColumnSpec(name="x", sql_type="INTEGER", nullable=False,
                     default="0")
    assert "NOT NULL DEFAULT 0" in col.render()


def test_column_spec_rejects_injection_in_type():
    with pytest.raises(MigrationError):
        ColumnSpec(name="ok", sql_type="TEXT); DROP TABLE targets;--")


def test_index_spec_requires_columns():
    with pytest.raises(MigrationError):
        IndexSpec(name="ix", table="targets", columns=())


def test_migration_rejects_bad_name_and_version():
    with pytest.raises(MigrationError):
        Migration(version=1, name="Bad-Name")
    with pytest.raises(MigrationError):
        Migration(version=0, name="ok")


def test_registry_is_contiguous_and_above_base():
    assert [m.version for m in MIGRATION_REGISTRY] == list(
        range(CURRENT_SCHEMA_VERSION + 1, REGISTRY_TOP_VERSION + 1)
    )


def test_schema_migrations_ddl_exposed():
    assert "schema_migrations" in schema_migrations_ddl()


# --------------------------------------------------------------------- #
# bootstrap + version reading
# --------------------------------------------------------------------- #


def test_fresh_db_reports_version_zero(engine):
    eng, _ = engine
    assert read_current_version(eng) == 0


def test_upgrade_bootstraps_full_schema(engine):
    eng, path = engine
    report = upgrade(eng, db_path=path)
    assert report.success
    info = snapshot_schema(eng)
    assert set(orm_table_names()) <= set(info.tables)
    assert info.version == REGISTRY_TOP_VERSION


def test_upgrade_is_idempotent(engine):
    eng, path = engine
    r1 = upgrade(eng, db_path=path)
    r2 = upgrade(eng, db_path=path)
    assert r1.success and r2.success
    assert r2.start_version == r2.end_version == REGISTRY_TOP_VERSION


def test_unversioned_foreign_schema_refuses_guessing(tmp_path):
    path = str(tmp_path / "foreign.db")
    eng = create_engine(f"sqlite:///{path}")
    try:
        with eng.begin() as c:
            c.execute(text("CREATE TABLE settings (key TEXT PRIMARY KEY)"))
        with pytest.raises(SchemaVersionError):
            read_current_version(eng)
    finally:
        eng.dispose()


# --------------------------------------------------------------------- #
# forward / backward migrations
# --------------------------------------------------------------------- #


def test_v2_adds_columns_and_indexes(engine):
    eng, path = engine
    rep = upgrade(eng, db_path=path)
    assert rep.success
    info = snapshot_schema(eng)
    assert "priority" in info.columns["events"]
    assert "expires_at" in info.columns["events"]
    assert "bucket_ts" in info.columns["telemetry_samples"]
    assert info.has_index("ix_events_priority_expires")
    # a backup was taken before the structural step
    assert rep.backup_path and os.path.exists(rep.backup_path)


def test_downgrade_then_reupgrade(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    down = downgrade(eng, CURRENT_SCHEMA_VERSION, db_path=path)
    assert down.success
    runner = MigrationRunner(eng, db_path=path)
    assert runner.current_version() == CURRENT_SCHEMA_VERSION
    up2 = upgrade(eng, db_path=path)
    assert up2.success
    assert runner.current_version() == REGISTRY_TOP_VERSION


def test_downgrade_below_base_refused(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    with pytest.raises(MigrationError):
        downgrade(eng, 0, db_path=path)


def test_upgrade_to_older_version_refused(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    if REGISTRY_TOP_VERSION > CURRENT_SCHEMA_VERSION:
        with pytest.raises(SchemaVersionError):
            MigrationRunner(eng).plan_upgrade(CURRENT_SCHEMA_VERSION)
    else:
        # base == head: planning "upgrade" to the same version is a no-op
        plan = MigrationRunner(eng).plan_upgrade(CURRENT_SCHEMA_VERSION)
        assert plan.is_empty


def test_history_rewrite_detected(engine):
    eng, path = engine
    if REGISTRY_TOP_VERSION <= CURRENT_SCHEMA_VERSION:
        pytest.skip("no forward migrations registered")
    upgrade(eng, db_path=path)
    tampered = Migration(
        version=MIGRATION_REGISTRY[0].version,
        name=MIGRATION_REGISTRY[0].name,
        description="tampered",
        adds_columns={"events": (ColumnSpec(name="extra_col",
                                            sql_type="TEXT"),)},
    )
    runner = MigrationRunner(eng, db_path=path)
    runner.registry = [tampered]
    plan = runner.plan_upgrade()
    # plan is empty because version already applied; force a re-run
    result = runner._run_step(tampered, MigrationDirection.UP)
    assert result.status in (MigrationStatus.FAILED,)
    assert "rewrite" in (result.error or "").lower()


# --------------------------------------------------------------------- #
# integrity, drift, backups
# --------------------------------------------------------------------- #


def test_integrity_check_passes(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    ok, detail = verify_integrity(eng)
    assert ok and detail == "ok"


def test_drift_detection_sees_manual_changes(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    assert not detect_drift(eng)["drifted"]
    with eng.begin() as c:
        c.execute(text("ALTER TABLE corpora ADD COLUMN rogue INTEGER"))
    d = detect_drift(eng)
    assert d["drifted"]
    assert "rogue" in d["extra_columns"]["corpora"]


def test_backup_roundtrip_content_preserved(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    with eng.begin() as c:
        c.execute(
            text(
                "INSERT INTO settings (key, value_json, category) "
                "VALUES ('canary', '\"42\"', 'test')"
            )
        )
    bak = backup_database_file(path)
    assert bak and os.path.exists(bak)
    check = create_engine(f"sqlite:///{bak}")
    try:
        with check.connect() as c:
            val = c.execute(
                text("SELECT value_json FROM settings WHERE key='canary'")
            ).scalar()
        assert val is not None
    finally:
        check.dispose()


def test_status_report_shape(engine):
    eng, path = engine
    upgrade(eng, db_path=path)
    st = migration_status(eng)
    assert st["integrity_ok"] is True
    assert st["live_version"] == REGISTRY_TOP_VERSION
    assert st["needs_upgrade"] is False
    assert isinstance(st["applied_migrations"], list)
    slugs = {m["slug"] for m in st["applied_migrations"]}
    assert any("bootstrap" in s for s in slugs)


def test_build_bootstrap_migration_lists_all_tables():
    boot = build_bootstrap_migration()
    assert boot.version == CURRENT_SCHEMA_VERSION
    assert len(boot.creates_tables) == len(orm_table_names())
    assert all(isinstance(t, TableSpec) for t in boot.creates_tables)
