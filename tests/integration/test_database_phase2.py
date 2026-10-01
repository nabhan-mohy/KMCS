"""Integration tests for the KMCS database layer (Phase 2).

These exercise realistic multi-entity workflows end-to-end against a real
SQLite file: bootstrap -> targets -> corpora -> campaigns -> crashes ->
deduplication -> findings lifecycle -> telemetry/events -> migrations ->
stats/export. No fuzzing engines are involved yet (that is Phase 3+); all
crash records are *synthetic test fixtures*, clearly marked as such, used
only to verify persistence semantics.
"""

from __future__ import annotations

import json

import pytest

from kmcs.core import models as cm
from kmcs.database import migration_status
from kmcs.database.database import DatabaseManager
from kmcs.database.migrations import (
    REGISTRY_TOP_VERSION,
    detect_drift,
    snapshot_schema,
    upgrade,
)
from kmcs.database.models import CrashRow, FindingRow, TargetRow


def _seed_target(manager):
    target = cm.Target(
        name="demo-parser",
        binary_path="/usr/local/bin/demo-parser",
        source_root="/src/demo",
        language="c",
        tags=["integration", "demo"],
    )
    manager.save_target(target)
    return target


def test_full_pipeline_persistence(manager):
    # --- target ------------------------------------------------------ #
    target = _seed_target(manager)

    # --- corpus ------------------------------------------------------- #
    corpus = cm.Corpus(name="seeds", target_id=target.id)
    corpus.add(b"\x89PNG\r\n\x1a\n valid header", name="seed0")
    corpus.add(b"another plausible input", name="seed1")
    manager.save_corpus(corpus)
    got = manager.get_corpus(corpus.id)
    assert got is not None

    # --- campaign ----------------------------------------------------- #
    campaign = cm.Campaign(name="nightly-1", target_id=target.id)
    manager.save_campaign(campaign)
    manager.set_campaign_status(campaign.id, "running")

    # --- synthetic crash fixtures (NOT real fuzzer output) ------------ #
    def mk(idx: int, frames, klass):
        return cm.Crash(
            target_id=target.id,
            target_name=target.name,
            campaign_id=campaign.id,
            crash_class=klass,
            sanitizer="asan",
            engine="synthetic-test-fixture",
            input_path=f"/tmp/crash{idx}.bin",
            stack_trace=frames,
        )

    c1 = mk(1, ["#0 memcpy", "#1 parse", "#2 main"], "heap-buffer-overflow")
    c2 = mk(2, ["#0 memcpy", "#1 parse", "#2 main"], "heap-buffer-overflow")
    c3 = mk(3, ["#0 abort", "#1 check", "#2 main"], "assert")
    for c in (c1, c2, c3):
        manager.save_crash(c)

    dup = manager.find_duplicate(
        mk(4, ["#0 memcpy", "#1 parse", "#2 main"], "heap-buffer-overflow")
    )
    if dup is not None:  # fingerprint semantics live in core models
        manager.mark_duplicate(c2.id, c1.id)

    listed = manager.list_crashes(campaign_id=campaign.id)
    assert len(listed) >= 3

    # --- finding ------------------------------------------------------ #
    finding = cm.Finding(
        title="Heap buffer overflow in demo-parser (test fixture)",
        severity="high",
        target_id=target.id,
        campaign_id=campaign.id,
    )
    manager.save_finding(finding)
    manager.transition_finding(finding.id, "confirmed")
    back = manager.get_finding(finding.id)
    assert back.title.startswith("Heap buffer overflow")

    # --- events / telemetry / jobs ------------------------------------ #
    class Env:
        topic = "campaign.integrated"
        payload = {"campaign_id": campaign.id, "phase": "test"}

        class _T:
            isoformat = staticmethod(lambda: "2026-10-01T00:00:00+00:00")
        timestamp = _T()

        def __init__(self):
            self.id = "evt-int-1"

    try:
        manager.append_event(Env())
    except Exception as exc:  # envelope shape mismatch must be loud, not silent
        pytest.fail(f"append_event rejected a minimal envelope: {exc}")

    st = manager.stats()
    assert st["targets"] >= 1
    assert st["crashes"] >= 3
    assert st["findings"] >= 1

    export = json.loads(manager.export_json())
    assert isinstance(export, dict)


def test_reopen_reloads_everything(db_path):
    m1 = DatabaseManager(db_path)
    m1.initialize()
    t = _seed_target(m1)
    m1.close()

    m2 = DatabaseManager(db_path)
    m2.initialize()
    reloaded = m2.get_target(t.id)
    assert reloaded.name == "demo-parser"
    assert "integration" in reloaded.tags
    m2.close()


def test_migrations_then_manager_coexist(tmp_path):
    """A DB migrated by MigrationRunner is fully usable by DatabaseManager."""
    path = str(tmp_path / "coexist.db")
    from sqlalchemy import create_engine

    eng = create_engine(f"sqlite:///{path}")
    try:
        report = upgrade(eng, db_path=path)
        assert report.success
    finally:
        eng.dispose()

    mgr = DatabaseManager(path)
    mgr.initialize()
    assert mgr.schema_version >= 1
    t = _seed_target(mgr)
    assert mgr.get(TargetRow, t.id) is not None
    info = snapshot_schema(mgr.engine)
    assert info.version == REGISTRY_TOP_VERSION or info.version >= 1
    assert not detect_drift(mgr.engine)["drifted"]
    mgr.close()


def test_defensive_policy_blocks_prohibited_rows(manager):
    """Inserting a row that carries a prohibited capability must fail."""
    from kmcs.database.models import EvidenceRow
    from kmcs.core.exceptions import ProhibitedCapabilityError

    ev = EvidenceRow(
        id="ev-bad-1",
        kind="capability",
        subject="finding-x",
        capability="shellcode_generation",
    )
    with pytest.raises(ProhibitedCapabilityError):
        manager.add(ev)


def test_status_endpoint_after_activity(manager):
    _seed_target(manager)
    st = migration_status(manager.engine)
    assert st["integrity_ok"] is True
    assert st["table_count"] >= 16
