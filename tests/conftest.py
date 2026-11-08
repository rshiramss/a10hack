from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.harness import Harness, build_harness


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    built = build_harness(tmp_path)
    yield built
    built.conn.close()


@pytest.fixture
def trial(harness: Harness) -> Harness:
    """V-07 dispensed and ready to score: pharmacist, assessors A (slot 1) and B (slot 2)."""
    harness.tokens = {
        "pharm": harness.enroll("pharm-1", "pharmacist"),
        "a": harness.enroll("assessor-a", "assessor"),
        "b": harness.enroll("assessor-b", "assessor"),
        "c": harness.enroll("assessor-c", "assessor"),
        "adj": harness.enroll("adjud-1", "adjudicator"),
    }
    harness.setup_visit(
        "V-07", pharmacist="pharm-1", slot1="assessor-a", slot2="assessor-b", adjudicator="adjud-1"
    )
    harness.dispense(harness.tokens["pharm"], "V-07")
    return harness
