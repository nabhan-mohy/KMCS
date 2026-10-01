"""Unit tests for kmcs.database.database (DatabaseManager, Phase 2)."""

from __future__ import annotations

import json
import threading

import pytest

from kmcs.core import models as cm
from kmcs.core.exceptions import DatabaseError, RecordNotFoundError
from kmcs.database.database import (
    DatabaseManager,
    DEFAULT_DB_FILENAME,
    default_database_path,
)
from kmcs.database.models import CrashRow, SettingRow, TargetRow


def test_default_path_shape(tmp_path):
    p = default_database_path(tmp_path)
    assert p.endswith(DEFAULT_DB_FILENAME)
    assert ".kmcs" in p


def test_initialize_creates_schema_and_stamp(manager):
    assert manager.schema_version >= 1
    assert manager.get(SettingRow, "schema.version") is not None


def test_initialize_is_idempotent(db_path):
    m1 = DatabaseManager(db_path)
    m1.initialize()
    m1.close()
    m2 = DatabaseManager(db_path)
    m2.initialize()  # must not raise
    assert m2.schema_version >= 1
    m2.close()


def test_get_or_raise_missing(manager):
    with pytest.raises(RecordNotFoundError):
        manager.get_or_raise(TargetRow, "does-not-exist")


def test_save_and_list_targets(manager):
    for i in range(3):
        manager.save_target(cm.Target(name=f"t{i}", binary_path="/bin/true"))
    rows = manager.list_targets()
    assert len(rows) == 3
    some = manager.list_targets(name_like="t1")
    assert len(some) == 1


def test_delete_target(manager):
    t = cm.Target(name="gone", binary_path="/bin/true")
    manager.save_target(t)
    assert manager.delete_target(t.id) is True
    assert manager.delete_target(t.id) is False


def test_campaign_lifecycle(manager):
    target = cm.Target(name="camp-target", binary_path="/bin/true")
    manager.save_target(target)
    camp = cm.Campaign(name="run-1", target_id=target.id)
    manager.save_campaign(camp)
    got = manager.get_campaign(camp.id)
    assert got.target_id == target.id
    manager.set_campaign_status(camp.id, "running")
    rows = manager.list_campaigns(target_id=target.id)
    assert any(str(r.status) != "" for r in rows)


def test_crash_duplicate_detection(manager):
    crash_a = cm.Crash(
        target_id="tgt-x", campaign_id="camp-x",
        crash_class="heap-buffer-overflow", sanitizer="asan",
        input_path="/tmp/a.bin",
        stack_trace=["#0 memcpy", "#1 parse_chunk", "#2 main"],
    )
    crash_b = cm.Crash(
        target_id="tgt-x", campaign_id="camp-x",
        crash_class="heap-buffer-overflow", sanitizer="asan",
        input_path="/tmp/b.bin",
        stack_trace=["#0 memcpy", "#1 parse_chunk", "#2 main"],
    )
    manager.save_crash(crash_a)
    dup = manager.find_duplicate(crash_b)
    # identical traces/class/sanitizer should fingerprint together
    assert dup is not None, "identical crash was not deduplicated"
    assert dup.id == crash_a.id
    # second occurrence recorded, then linked as duplicate of the first
    manager.save_crash(crash_b)
    marked = manager.mark_duplicate(crash_b.id, crash_a.id)
    assert marked is not None
    group = manager.crashes_by_fingerprint(
        crash_a.fingerprint.digest
        if getattr(crash_a, "fingerprint", None)
        else (manager.get(CrashRow, crash_a.id).fingerprint_digest
              or "")
    )
    assert isinstance(group, list)


def test_settings_roundtrip_and_categories(manager):
    manager.set_setting("a.b", 42, category="test")
    manager.set_setting("c.d", {"x": [1, 2]}, category="test")
    assert manager.get_setting("a.b") == 42
    assert manager.get_setting("missing", default="fallback") == "fallback"
    allin = manager.all_settings(category="test")
    assert "a.b" in allin and "c.d" in allin


def test_stats_keys(manager):
    st = manager.stats()
    for key in ("targets", "campaigns", "crashes", "findings"):
        assert key in st
        assert isinstance(st[key], int) or isinstance(st[key], dict)


def test_transaction_rollback(db_path):
    mgr = DatabaseManager(db_path)
    mgr.initialize()
    try:
        t = cm.Target(name="rolled-back", binary_path="/bin/true")
        row = TargetRow.from_domain(t)
        with pytest.raises(RuntimeError):
            with mgr.transaction() as session:
                session.add(row)
                session.flush()
                raise RuntimeError("boom")
        assert mgr.get(TargetRow, t.id) is None
    finally:
        mgr.close()


def test_concurrent_writes(db_path):
    mgr = DatabaseManager(db_path)
    mgr.initialize()
    errors = []

    def worker(n):
        try:
            for i in range(5):
                mgr.save_target(
                    cm.Target(name=f"w{n}-{i}", binary_path="/bin/true")
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors, errors
    assert mgr.count(TargetRow) == 20
    mgr.close()


def test_closed_manager_rejects_work(db_path):
    mgr = DatabaseManager(db_path)
    mgr.initialize()
    mgr.close()
    with pytest.raises(DatabaseError):
        mgr.initialize()


def test_export_json_is_valid(manager):
    manager.save_target(cm.Target(name="exp", binary_path="/bin/true"))
    payload = manager.export_json()
    data = json.loads(payload)
    assert isinstance(data, dict)


def test_integrity_check_clean(manager):
    result = manager.integrity_check()
    assert result == [] or result == ["ok"] or all(
        str(r) == "ok" for r in result
    )
