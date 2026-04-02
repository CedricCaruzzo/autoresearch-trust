"""
Tests for trust/evaluator.py — isolated subprocess evaluation with nonce provenance.

The actual torch-based evaluation (evaluate_bpb) is not tested here — that
requires an H100 and downloaded data. These tests cover the orchestration
layer: nonce generation, storage, subprocess wiring, result parsing, and
provenance verification.

The subprocess call is mocked using a real helper script so we can test the
full code path without torch.
"""

import subprocess
import sys
import textwrap
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from trust.evaluator import (
    generate_and_store_nonce,
    run_isolated_eval,
    verify_eval_provenance,
    EvaluatorError,
    _parse_val_bpb,
)
from trust.ledger import open_run


@pytest.fixture
def db(tmp_path) -> Path:
    return tmp_path / "trust.db"


@pytest.fixture
def run_id(db) -> int:
    return open_run(db, script="train.py")


@pytest.fixture
def fake_checkpoint(tmp_path) -> Path:
    p = tmp_path / "checkpoint.pt"
    p.write_bytes(b"fake")
    return p


@pytest.fixture
def fake_prepare(tmp_path) -> Path:
    p = tmp_path / "prepare.py"
    p.write_text("# fake prepare\n")
    return p


# ---------------------------------------------------------------------------
# Nonce generation
# ---------------------------------------------------------------------------

def test_nonce_generated_and_stored(db, run_id):
    nonce = generate_and_store_nonce(db, run_id)
    assert len(nonce) == 32  # 16 bytes → 32 hex chars
    assert nonce.isalnum()


def test_nonce_is_unique_per_run(db):
    rid1 = open_run(db, script="train.py")
    rid2 = open_run(db, script="train.py")
    n1 = generate_and_store_nonce(db, rid1)
    n2 = generate_and_store_nonce(db, rid2)
    assert n1 != n2


def test_nonce_stored_with_checkpoint_path(db, run_id, fake_checkpoint):
    generate_and_store_nonce(db, run_id, checkpoint_path=fake_checkpoint)
    import sqlite3
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM eval_nonces WHERE run_id = ?", (run_id,)).fetchone()
    conn.close()
    assert row["checkpoint_path"] == str(fake_checkpoint)


# ---------------------------------------------------------------------------
# _parse_val_bpb
# ---------------------------------------------------------------------------

def test_parse_val_bpb_from_stdout():
    stdout = "eval_worker: nonce=abc\nval_bpb: 0.997900\n"
    assert _parse_val_bpb(stdout) == pytest.approx(0.997900)


def test_parse_val_bpb_returns_none_when_absent():
    assert _parse_val_bpb("some other output\n") is None


def test_parse_val_bpb_handles_extra_whitespace():
    assert _parse_val_bpb("val_bpb:   1.234000  \n") == pytest.approx(1.234)


# ---------------------------------------------------------------------------
# run_isolated_eval (mocked subprocess)
# ---------------------------------------------------------------------------

def _make_mock_proc(stdout="val_bpb: 0.991200\n", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


def test_run_isolated_eval_success(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id, checkpoint_path=fake_checkpoint)

    with patch("subprocess.run", return_value=_make_mock_proc("val_bpb: 0.991200\n")):
        result = run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)

    assert result.val_bpb == pytest.approx(0.991200)
    assert len(result.nonce) == 32


def test_run_isolated_eval_stores_result(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id, checkpoint_path=fake_checkpoint)

    with patch("subprocess.run", return_value=_make_mock_proc("val_bpb: 0.991200\n")):
        run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)

    import sqlite3
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM eval_nonces WHERE run_id = ?", (run_id,)).fetchone()
    conn.close()
    assert row["val_bpb"] == pytest.approx(0.991200)
    assert row["completed_at"] is not None


def test_run_isolated_eval_raises_on_nonzero_exit(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id)
    with patch("subprocess.run", return_value=_make_mock_proc("ERROR: crash", returncode=1)):
        with pytest.raises(EvaluatorError, match="exited with code"):
            run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)


def test_run_isolated_eval_raises_on_timeout(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1)):
        with pytest.raises(EvaluatorError, match="timed out"):
            run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare, timeout=1)


def test_run_isolated_eval_raises_on_unparseable_output(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id)
    with patch("subprocess.run", return_value=_make_mock_proc("no metric here\n")):
        with pytest.raises(EvaluatorError, match="no parseable val_bpb"):
            run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)


def test_run_isolated_eval_raises_when_no_nonce(db, run_id, fake_checkpoint, fake_prepare):
    # No nonce stored for this run
    with pytest.raises(EvaluatorError, match="No eval nonce"):
        run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)


# ---------------------------------------------------------------------------
# Provenance verification
# ---------------------------------------------------------------------------

def test_provenance_ok_when_all_complete(db, run_id, fake_checkpoint, fake_prepare):
    generate_and_store_nonce(db, run_id, checkpoint_path=fake_checkpoint)
    with patch("subprocess.run", return_value=_make_mock_proc("val_bpb: 0.99\n")):
        run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)

    ok, violations = verify_eval_provenance(db)
    assert ok
    assert violations == []


def test_provenance_missing_db(db):
    ok, violations = verify_eval_provenance(db)
    assert not ok
    assert any("not found" in v for v in violations)


def test_nonce_passes_to_worker_command(db, run_id, fake_checkpoint, fake_prepare):
    """Verify the nonce is included in the subprocess command."""
    nonce = generate_and_store_nonce(db, run_id)
    calls = []

    def capture_run(cmd, **kwargs):
        calls.append(cmd)
        return _make_mock_proc("val_bpb: 0.99\n")

    with patch("subprocess.run", side_effect=capture_run):
        run_isolated_eval(db, run_id, fake_checkpoint, fake_prepare)

    assert "--nonce" in calls[0]
    nonce_idx = calls[0].index("--nonce")
    assert calls[0][nonce_idx + 1] == nonce
