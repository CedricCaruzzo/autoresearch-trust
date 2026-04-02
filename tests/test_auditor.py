"""
Tests for trust/auditor.py — statistical anomaly detection.

Each test constructs a specific run history and asserts the auditor produces
the expected finding codes. Tests are organised by the anomaly they target.
"""

import pytest
from pathlib import Path

from trust.auditor import audit, ANOMALY, WARNING, INFO
from trust.ledger import open_run, close_run
from trust.hypothesis import commit_hypothesis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_run(db, *, val_bpb, status, description, direction=None, rationale=None):
    """Open, optionally commit a hypothesis, then close a run."""
    run_id = open_run(db, script="train.py")
    if direction and rationale:
        commit_hypothesis(db, run_id, rationale=rationale, direction=direction)
    close_run(db, run_id, val_bpb=val_bpb, status=status, description=description)
    return run_id


def finding_codes(report):
    return {f.code for f in report.findings}


def anomaly_codes(report):
    return {f.code for f in report.findings if f.severity == ANOMALY}


def warning_codes(report):
    return {f.code for f in report.findings if f.severity == WARNING}


@pytest.fixture
def db(tmp_path) -> Path:
    return tmp_path / "trust.db"


# ---------------------------------------------------------------------------
# No-ledger edge case
# ---------------------------------------------------------------------------

def test_missing_ledger_is_anomaly(db):
    report = audit(db)
    assert "NO_LEDGER" in anomaly_codes(report)


# ---------------------------------------------------------------------------
# Chain integrity
# ---------------------------------------------------------------------------

def test_clean_chain_reports_ok(db):
    make_run(db, val_bpb=1.00, status="keep", description="baseline")
    report = audit(db)
    assert "CHAIN_OK" in finding_codes(report)
    assert "CHAIN_BROKEN" not in anomaly_codes(report)


def test_broken_chain_is_anomaly(db):
    import sqlite3
    for i in range(3):
        make_run(db, val_bpb=1.0 - i * 0.01, status="keep", description=f"run {i}")

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM runs WHERE id = 2")
    conn.commit()
    conn.close()

    report = audit(db)
    assert "CHAIN_BROKEN" in anomaly_codes(report)


# ---------------------------------------------------------------------------
# ID gaps
# ---------------------------------------------------------------------------

def test_no_id_gaps_reports_clean(db):
    for i in range(3):
        make_run(db, val_bpb=1.0, status="discard", description=f"run {i}")
    report = audit(db)
    assert "NO_ID_GAPS" in finding_codes(report)


def test_id_gap_is_anomaly(db):
    import sqlite3
    for i in range(4):
        make_run(db, val_bpb=1.0, status="discard", description=f"run {i}")

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM runs WHERE id = 2")
    conn.commit()
    conn.close()

    report = audit(db)
    assert "ID_GAPS" in anomaly_codes(report)


# ---------------------------------------------------------------------------
# Unclosed runs
# ---------------------------------------------------------------------------

def test_unclosed_run_is_warning(db):
    open_run(db, script="train.py")  # never closed
    report = audit(db)
    assert "UNCLOSED_RUNS" in warning_codes(report)


def test_all_closed_no_unclosed_warning(db):
    make_run(db, val_bpb=1.0, status="keep", description="baseline")
    report = audit(db)
    assert "UNCLOSED_RUNS" not in warning_codes(report)


# ---------------------------------------------------------------------------
# Missing hypotheses
# ---------------------------------------------------------------------------

def test_missing_hypothesis_warning_above_threshold(db):
    # 6 runs, none with hypotheses — well above the 20% threshold
    for i in range(6):
        make_run(db, val_bpb=1.0 - i * 0.01, status="keep", description=f"run {i}")
    report = audit(db)
    assert "MISSING_HYPOTHESES" in warning_codes(report)


def test_no_missing_hypothesis_warning_when_covered(db):
    bpb = [1.00, 0.99, 0.98, 0.97, 0.96, 0.95]
    directions = ["improve"] * 6
    for i in range(6):
        make_run(
            db, val_bpb=bpb[i], status="keep", description=f"run {i}",
            direction=directions[i], rationale=f"rationale {i}",
        )
    report = audit(db)
    assert "MISSING_HYPOTHESES" not in warning_codes(report)


# ---------------------------------------------------------------------------
# Keep rate
# ---------------------------------------------------------------------------

def test_high_keep_rate_with_no_discards_is_warning(db):
    for i in range(8):
        make_run(
            db, val_bpb=1.0 - i * 0.01, status="keep", description=f"run {i}",
            direction="improve", rationale="rationale",
        )
    report = audit(db)
    assert "HIGH_KEEP_RATE" in warning_codes(report)


def test_mixed_statuses_no_high_keep_warning(db):
    statuses = ["keep", "discard", "keep", "crash", "keep", "discard"]
    for i, s in enumerate(statuses):
        make_run(db, val_bpb=1.0 - i * 0.005, status=s, description=f"run {i}",
                 direction="improve", rationale="rationale")
    report = audit(db)
    assert "HIGH_KEEP_RATE" not in warning_codes(report)


# ---------------------------------------------------------------------------
# Direction accuracy
# ---------------------------------------------------------------------------

def test_low_direction_accuracy_is_warning(db):
    # Agent consistently predicts 'improve' but results degrade — below chance
    bpb = [1.00, 1.01, 1.02, 1.03, 1.04, 1.05]  # consistently degrading
    for i in range(6):
        make_run(
            db, val_bpb=bpb[i], status="discard", description=f"run {i}",
            direction="improve",   # always predicts improve — always wrong
            rationale="rationale",
        )
    report = audit(db)
    assert "LOW_DIRECTION_ACCURACY" in warning_codes(report)


def test_good_direction_accuracy_no_warning(db):
    # Agent correctly predicts 'improve' and val_bpb actually drops
    bpb = [1.00, 0.99, 0.98, 0.97, 0.96, 0.95]
    for i in range(6):
        make_run(
            db, val_bpb=bpb[i], status="keep", description=f"run {i}",
            direction="improve", rationale="rationale",
        )
    report = audit(db)
    assert "LOW_DIRECTION_ACCURACY" not in warning_codes(report)


# ---------------------------------------------------------------------------
# Monotone improvement
# ---------------------------------------------------------------------------

def test_monotone_improvement_is_warning(db):
    # Perfect monotone improvement — every kept run strictly better than the last
    for i in range(6):
        make_run(
            db, val_bpb=1.00 - i * 0.01, status="keep", description=f"run {i}",
            direction="improve", rationale="rationale",
        )
    report = audit(db)
    assert "MONOTONE_IMPROVEMENT" in warning_codes(report)


def test_non_monotone_improvement_no_warning(db):
    # Realistic: one lateral move, one slight regression among keeps
    bpb = [1.00, 0.99, 0.992, 0.988, 0.985, 0.981]
    for i in range(6):
        make_run(
            db, val_bpb=bpb[i], status="keep", description=f"run {i}",
            direction="improve", rationale="rationale",
        )
    report = audit(db)
    assert "MONOTONE_IMPROVEMENT" not in warning_codes(report)


# ---------------------------------------------------------------------------
# Insufficient data guard
# ---------------------------------------------------------------------------

def test_insufficient_data_skips_stats(db):
    # Only 2 closed runs — below MIN_RUNS_FOR_STATS
    for i in range(2):
        make_run(db, val_bpb=1.0 - i * 0.01, status="keep", description=f"run {i}")
    report = audit(db)
    assert "INSUFFICIENT_DATA" in finding_codes(report)
    # Statistical checks should not fire on tiny samples
    assert "HIGH_KEEP_RATE" not in warning_codes(report)
    assert "MONOTONE_IMPROVEMENT" not in warning_codes(report)
