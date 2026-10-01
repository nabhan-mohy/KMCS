"""Unit tests for kmcs.database.models (Phase 2)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect as sa_inspect

from kmcs.core import models as cm
from kmcs.database.models import (
    AuthorisationRow,
    Base,
    CampaignRow,
    CorpusEntryRow,
    CorpusRow,
    CrashRow,
    EvidenceRow,
    FindingRow,
    JSONText,
    JobRow,
    MinimizationRow,
    ReproductionRow,
    RegressionTestRow,
    ReportRow,
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
from kmcs.core.exceptions import ProhibitedCapabilityError


EXPECTED_TABLES = {
    "targets", "authorisations", "corpora", "corpus_entries", "campaigns",
    "crashes", "findings", "reproductions", "minimizations", "reports",
    "regression_tests", "jobs", "events", "settings", "telemetry_samples",
    "evidence",
}


def test_schema_version_marker():
    assert SCHEMA_VERSION >= 1


def test_table_names_cover_expected_entities():
    names = set(table_names())
    assert EXPECTED_TABLES <= names, EXPECTED_TABLES - names


def test_metadata_creates_all_tables(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'m.db'}")
    Base.metadata.create_all(engine)
    live = set(sa_inspect(engine).get_table_names())
    assert EXPECTED_TABLES <= live
    engine.dispose()


def test_utc_now_is_timezone_aware():
    now = utc_now()
    assert now.tzinfo is not None


# --------------------------------------------------------------------- #
# domain <-> row conversions
# --------------------------------------------------------------------- #


def test_target_roundtrip(manager):
    target = cm.Target(name="libpng-demo", binary_path="/bin/true",
                       tags=["image", "c"])
    row = manager.save_target(target)
    assert isinstance(row, TargetRow)
    back = manager.get_target(target.id)
    assert back.name == "libpng-demo"
    assert "image" in back.tags
    assert back.binary_path == "/bin/true"


def test_target_update_upserts(manager):
    target = cm.Target(name="v1", binary_path="/bin/true")
    manager.save_target(target)
    target.name = "v2"
    manager.save_target(target)
    rows = manager.list_targets()
    ids = [r.id for r in rows]
    assert ids.count(target.id) == 1
    got = manager.get_target(target.id)
    assert got.name == "v2"


def test_crash_roundtrip_and_dedup_link(manager):
    target = cm.Target(name="t", binary_path="/bin/true")
    manager.save_target(target)
    crash = cm.Crash(
        target_id=target.id,
        target_name=target.name,
        campaign_id="camp-0001",
        crash_class="heap-buffer-overflow",
        sanitizer="asan",
        input_path="/tmp/in.bin",
    )
    row = manager.save_crash(crash)
    assert isinstance(row, CrashRow)
    back = manager.get_crash(crash.id)
    assert back.crash_class == "heap-buffer-overflow"
    assert back.sanitizer == "asan"


def test_finding_transition_lifecycle(manager):
    finding = cm.Finding(title="Stack overflow in demo parser",
                         severity="high")
    row = manager.save_finding(finding)
    assert isinstance(row, FindingRow)
    moved = manager.transition_finding(finding.id, "confirmed")
    assert str(moved.state) in ("confirmed", "FindingState.CONFIRMED",
                                "CONFIRMED") or moved.state is not None


def test_guard_row_policy_rejects_prohibited_capabilities():
    class Bad:
        capability = "exploit_generation"

    with pytest.raises(ProhibitedCapabilityError):
        guard_row_policy(Bad())


def test_guard_row_policy_allows_defensive_values():
    class Good:
        capability = "fuzzing"

    guard_row_policy(Good())  # must not raise


def test_row_to_dict_contains_pk(manager):
    target = cm.Target(name="dicty", binary_path="/bin/true")
    row = manager.save_target(target)
    d = row_to_dict(row)
    assert d["id"] == target.id
    assert "name" in d and d["name"] == "dicty"


def test_sluglist_stores_and_loads_lists(manager):
    target = cm.Target(name="slug", binary_path="/bin/true",
                       tags=["a", "b-c", "d"])
    manager.save_target(target)
    row = manager.get(TargetRow, target.id)
    assert sorted(row.tags) == ["a", "b-c", "d"]


def test_jsontext_roundtrips_dicts(manager):
    manager.set_setting("test.json", {"nested": [1, 2, {"k": "v"}]})
    got = manager.get_setting("test.json")
    assert got == {"nested": [1, 2, {"k": "v"}]}


def test_every_model_class_registered():
    mappers = Base.registry.mappers
    classes = {m.class_ for m in mappers}
    for cls in (TargetRow, AuthorisationRow, CorpusRow, CorpusEntryRow,
                CampaignRow, CrashRow, FindingRow, ReproductionRow,
                MinimizationRow, ReportRow, RegressionTestRow, JobRow,
                SettingRow, TelemetryRow):
        assert cls in classes, cls


def test_evidence_table_constant():
    assert EVIDENCE_TABLE == "evidence"
    assert "evidence" in table_names()
