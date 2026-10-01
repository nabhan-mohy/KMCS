"""Shared pytest fixtures for the KMCS test-suite (Phase 2 focus)."""

from __future__ import annotations

import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "kmcs_test.db")


@pytest.fixture()
def manager(db_path):
    from kmcs.database.database import DatabaseManager

    mgr = DatabaseManager(db_path)
    mgr.initialize()
    try:
        yield mgr
    finally:
        mgr.close()
