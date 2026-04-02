"""
Evaluator layer — isolated subprocess evaluation with nonce provenance.

How it works
------------
Instead of trusting the val_bpb number the agent reports (which it could
fabricate), this layer runs evaluation independently:

1. ``generate_and_store_nonce()`` — before the agent script runs, a random
   nonce is generated and stored in the ``eval_nonces`` table. This nonce
   is the provenance anchor for this run's evaluation.

2. ``run_isolated_eval()`` — after the agent script produces a checkpoint,
   this launches trust._eval_worker as a fresh subprocess. The worker:
   - loads the checkpoint (read-only)
   - imports evaluate_bpb() from the manifest-verified prepare.py
   - runs the evaluation
   - prints val_bpb to stdout

   Because the worker runs in a separate process, the agent's in-memory
   state, any monkey-patched functions, or any modified imports are gone.
   The eval runs against the clean, verified prepare.py.

3. ``verify_eval_provenance()`` — checks that every closed run that used
   the evaluator has a matching nonce record.

Why process isolation matters
------------------------------
If the agent modifies train.py to monkey-patch evaluate_bpb() at import
time, that patch only lives in the training process. The eval worker
starts a fresh Python interpreter — the patch is gone. The manifest check
already ensures the prepare.py file on disk is unmodified; process
isolation ensures the runtime is also clean.

The nonce limitation
--------------------
Full nonce injection into the validation dataloader's sampling order
would require modifying prepare.py's make_dataloader() — which is a
protected file. Today the nonce is a provenance record: it proves which
evaluation run corresponds to which training run. A production system
would store the nonce externally (e.g. in a TEE) and use it to seed
document shuffling inside a protected eval enclave, making overfitting
to a fixed val set detectable over time via per-nonce score variance.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS eval_nonces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL UNIQUE,
    nonce           TEXT    NOT NULL,
    generated_at    REAL    NOT NULL,
    checkpoint_path TEXT,                   -- path the worker will load
    val_bpb         REAL,                   -- result from the isolated eval
    worker_stdout   TEXT,                   -- full worker output for audit
    completed_at    REAL                    -- NULL until eval finishes
);
"""


class EvaluatorError(Exception):
    """Raised when the isolated evaluator fails."""


@dataclass
class EvalResult:
    val_bpb: float
    nonce: str
    stdout: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

@contextmanager
def _connect(db_path: Path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _parse_val_bpb(stdout: str) -> float | None:
    """Extract val_bpb from worker stdout. Looks for 'val_bpb: <float>'."""
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("val_bpb:"):
            try:
                return float(line.split(":", 1)[1].strip())
            except ValueError:
                pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_and_store_nonce(
    db_path: Path,
    run_id: int,
    checkpoint_path: Path | None = None,
) -> str:
    """
    Generate a fresh random nonce for this run and persist it.

    Must be called BEFORE the agent script runs so the nonce pre-dates
    the result — making it a genuine commitment, not a post-hoc label.

    Returns the nonce hex string.
    """
    nonce = secrets.token_hex(16)
    generated_at = time.time()

    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO eval_nonces
               (run_id, nonce, generated_at, checkpoint_path)
               VALUES (?, ?, ?, ?)""",
            (run_id, nonce, generated_at,
             str(checkpoint_path) if checkpoint_path else None),
        )
    return nonce


def run_isolated_eval(
    db_path: Path,
    run_id: int,
    checkpoint_path: Path,
    prepare_py_path: Path,
    *,
    timeout: int = 600,
) -> EvalResult:
    """
    Run evaluation in an isolated subprocess and return the result.

    The subprocess (trust._eval_worker) starts a fresh Python interpreter,
    imports evaluate_bpb() from prepare_py_path, loads the checkpoint, and
    prints 'val_bpb: X.XXXXXX' to stdout.

    Stores the result back into the eval_nonces table.
    Raises EvaluatorError on timeout, non-zero exit, or unparseable output.
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT nonce FROM eval_nonces WHERE run_id = ?", (run_id,)
        ).fetchone()

    if row is None:
        raise EvaluatorError(
            f"No eval nonce found for run {run_id}. "
            "Call generate_and_store_nonce() before run_isolated_eval()."
        )
    nonce = row["nonce"]

    cmd = [
        sys.executable, "-m", "trust._eval_worker",
        "--checkpoint", str(checkpoint_path),
        "--prepare", str(prepare_py_path),
        "--nonce", nonce,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise EvaluatorError(
            f"Eval worker timed out after {timeout}s for run {run_id}."
        )

    stdout = proc.stdout + proc.stderr

    if proc.returncode != 0:
        raise EvaluatorError(
            f"Eval worker exited with code {proc.returncode} for run {run_id}.\n"
            f"Output:\n{stdout}"
        )

    val_bpb = _parse_val_bpb(proc.stdout)
    if val_bpb is None:
        raise EvaluatorError(
            f"Eval worker produced no parseable val_bpb for run {run_id}.\n"
            f"stdout:\n{proc.stdout}"
        )

    completed_at = time.time()
    with _connect(db_path) as conn:
        conn.execute(
            """UPDATE eval_nonces
               SET val_bpb=?, worker_stdout=?, completed_at=?,
                   checkpoint_path=?
               WHERE run_id=?""",
            (val_bpb, stdout, completed_at, str(checkpoint_path), run_id),
        )

    return EvalResult(val_bpb=val_bpb, nonce=nonce, stdout=stdout)


def verify_eval_provenance(db_path: Path) -> tuple[bool, list[str]]:
    """
    Check that every completed eval has a nonce and a result.

    Returns (ok, violations).
    """
    if not db_path.exists():
        return False, [f"Ledger not found: {db_path}"]

    violations: list[str] = []

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM eval_nonces ORDER BY id ASC"
        ).fetchall()

    for row in rows:
        if row["completed_at"] is not None and row["val_bpb"] is None:
            violations.append(
                f"EVAL_MISSING_RESULT run_id={row['run_id']}: "
                "eval completed but no val_bpb recorded."
            )

    return len(violations) == 0, violations
