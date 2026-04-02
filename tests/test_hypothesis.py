"""
Tests for trust/hypothesis.py — pre-run prediction commitment.

Each test targets a specific property the hypothesis layer is designed to guarantee.
"""

import json
import sqlite3
import pytest
from pathlib import Path

from trust.hypothesis import (
    commit_hypothesis,
    get_hypothesis,
    verify_hypothesis_integrity,
    list_hypotheses,
    HypothesisError,
    _compute_commit_hash,
)
from trust.ledger import open_run


@pytest.fixture
def db(tmp_path) -> Path:
    return tmp_path / "trust.db"


@pytest.fixture
def run_id(db) -> int:
    return open_run(db, script="train.py")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_commit_and_retrieve(db, run_id):
    hyp_id = commit_hypothesis(
        db, run_id,
        rationale="Increasing learning rate should converge faster.",
        direction="improve",
        predicted_bpb=0.985,
    )
    h = get_hypothesis(db, run_id)
    assert h is not None
    assert h.id == hyp_id
    assert h.run_id == run_id
    assert h.direction == "improve"
    assert h.predicted_bpb == pytest.approx(0.985)
    assert h.rationale == "Increasing learning rate should converge faster."


def test_commit_without_predicted_bpb(db, run_id):
    commit_hypothesis(db, run_id, rationale="Trying wider MLP.", direction="neutral")
    h = get_hypothesis(db, run_id)
    assert h.predicted_bpb is None


def test_integrity_passes_on_clean_db(db, run_id):
    commit_hypothesis(db, run_id, rationale="Test.", direction="improve")
    ok, violations = verify_hypothesis_integrity(db)
    assert ok
    assert violations == []


def test_commit_hash_is_deterministic(db, run_id):
    """Same inputs always produce the same commit hash."""
    h1 = commit_hypothesis(db, run_id, rationale="r", direction="improve", predicted_bpb=0.99)
    h = get_hypothesis(db, run_id)
    expected = _compute_commit_hash(run_id, h.committed_at, "r", "improve", 0.99)
    assert h.commit_hash == expected


def test_all_valid_directions(db):
    for i, direction in enumerate(("improve", "degrade", "neutral")):
        rid = open_run(db, script="train.py")
        commit_hypothesis(db, rid, rationale="test", direction=direction)
    assert len(list_hypotheses(db)) == 3


# ---------------------------------------------------------------------------
# Threat: agent alters hypothesis after committing (post-hoc rationalisation)
# ---------------------------------------------------------------------------

def test_detect_rationale_tampering(db, run_id):
    """Detects when the rationale is rewritten after commitment."""
    commit_hypothesis(db, run_id, rationale="Original honest prediction.", direction="improve")

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE hypotheses SET rationale = ? WHERE run_id = ?",
        ("Rewritten to match the actual result.", run_id),
    )
    conn.commit()
    conn.close()

    ok, violations = verify_hypothesis_integrity(db)
    assert not ok
    assert any("HYPOTHESIS TAMPERED" in v for v in violations)


def test_detect_direction_tampering(db, run_id):
    """Detects when direction is flipped from 'degrade' to 'improve' after the fact."""
    commit_hypothesis(db, run_id, rationale="Risky change.", direction="degrade")

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE hypotheses SET direction = 'improve' WHERE run_id = ?", (run_id,)
    )
    conn.commit()
    conn.close()

    ok, violations = verify_hypothesis_integrity(db)
    assert not ok
    assert any("HYPOTHESIS TAMPERED" in v for v in violations)


def test_detect_predicted_bpb_tampering(db, run_id):
    """Detects when the predicted value is altered after the result is known."""
    commit_hypothesis(db, run_id, rationale="Should improve.", direction="improve", predicted_bpb=1.05)

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE hypotheses SET predicted_bpb = 0.95 WHERE run_id = ?", (run_id,)
    )
    conn.commit()
    conn.close()

    ok, violations = verify_hypothesis_integrity(db)
    assert not ok
    assert any("HYPOTHESIS TAMPERED" in v for v in violations)


# ---------------------------------------------------------------------------
# Error conditions
# ---------------------------------------------------------------------------

def test_invalid_direction_raises(db, run_id):
    with pytest.raises(HypothesisError, match="Invalid direction"):
        commit_hypothesis(db, run_id, rationale="test", direction="win")


def test_empty_rationale_raises(db, run_id):
    with pytest.raises(HypothesisError, match="non-empty"):
        commit_hypothesis(db, run_id, rationale="   ", direction="improve")


def test_get_hypothesis_returns_none_when_absent(db, run_id):
    assert get_hypothesis(db, run_id) is None


def test_verify_missing_db(db):
    ok, violations = verify_hypothesis_integrity(db)
    assert not ok
    assert any("not found" in v for v in violations)


def test_list_hypotheses_empty_db(db):
    assert list_hypotheses(db) == []
