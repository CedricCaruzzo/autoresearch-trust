"""
Hypothesis layer — pre-run prediction commitment.

How it works
------------
Before an experiment runs, the agent must declare:
  - what change it made to train.py and why (rationale)
  - the expected direction: 'improve', 'degrade', or 'neutral'
  - optionally, a predicted val_bpb value

This prediction is written to the ledger's ``hypotheses`` table and linked
to the run_id BEFORE the experiment executes. After the run, the actual
result sits alongside the committed prediction — making post-hoc
rationalisation visible.

Why this matters
----------------
A genuine researcher predicts correctly more often than chance, and their
errors are random. An agent gaming the metric shows a specific anomaly:
prediction accuracy near chance (hypotheses are noise), but results are
suspiciously good. That decoupling is the statistical signature the auditor
layer uses to flag gaming.

Limitation
----------
The agent could write deliberately vague hypotheses ("trying a change")
that are technically predictions but carry no information. Hypothesis
*quality* is a human judgement; this layer enforces that a prediction
*exists* and was committed before the run. Vague hypotheses are themselves
a signal: an agent confident in its approach should be able to predict
the direction.
"""

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


VALID_DIRECTIONS = ("improve", "degrade", "neutral")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hypotheses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,           -- foreign key → runs.id
    committed_at    REAL    NOT NULL,           -- unix timestamp
    rationale       TEXT    NOT NULL,           -- what change and why
    direction       TEXT    NOT NULL,           -- 'improve' | 'degrade' | 'neutral'
    predicted_bpb   REAL,                       -- optional numeric prediction
    commit_hash     TEXT    NOT NULL            -- SHA-256 of the commitment content
);
"""


class HypothesisError(Exception):
    """Raised when hypothesis validation or commitment fails."""


@dataclass
class HypothesisRecord:
    id: int
    run_id: int
    committed_at: float
    rationale: str
    direction: str
    predicted_bpb: float | None
    commit_hash: str


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


def _compute_commit_hash(run_id: int, committed_at: float, rationale: str,
                          direction: str, predicted_bpb: float | None) -> str:
    """Deterministic hash of the hypothesis content — proves it was not altered after commitment."""
    payload = {
        "run_id": run_id,
        "committed_at": committed_at,
        "rationale": rationale,
        "direction": direction,
        "predicted_bpb": predicted_bpb,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def commit_hypothesis(
    db_path: Path,
    run_id: int,
    *,
    rationale: str,
    direction: str,
    predicted_bpb: float | None = None,
) -> int:
    """
    Commit a hypothesis for a run BEFORE the experiment executes.

    ``rationale``     — what change was made and why (free text, must be non-empty)
    ``direction``     — expected outcome: 'improve', 'degrade', or 'neutral'
    ``predicted_bpb`` — optional numeric prediction

    Returns the hypothesis id.
    Raises HypothesisError if direction is invalid or rationale is empty.
    """
    rationale = rationale.strip()
    if not rationale:
        raise HypothesisError("Rationale must be non-empty.")
    if direction not in VALID_DIRECTIONS:
        raise HypothesisError(
            f"Invalid direction '{direction}'. Must be one of: {VALID_DIRECTIONS}."
        )

    committed_at = time.time()
    commit_hash = _compute_commit_hash(run_id, committed_at, rationale, direction, predicted_bpb)

    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO hypotheses
               (run_id, committed_at, rationale, direction, predicted_bpb, commit_hash)
               VALUES (?,?,?,?,?,?)""",
            (run_id, committed_at, rationale, direction, predicted_bpb, commit_hash),
        )
        return cur.lastrowid


def get_hypothesis(db_path: Path, run_id: int) -> HypothesisRecord | None:
    """Return the hypothesis committed for a run, or None if none exists."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM hypotheses WHERE run_id = ?", (run_id,)
        ).fetchone()
    if row is None:
        return None
    return HypothesisRecord(
        id=row["id"],
        run_id=row["run_id"],
        committed_at=row["committed_at"],
        rationale=row["rationale"],
        direction=row["direction"],
        predicted_bpb=row["predicted_bpb"],
        commit_hash=row["commit_hash"],
    )


def verify_hypothesis_integrity(db_path: Path) -> tuple[bool, list[str]]:
    """
    Re-compute every hypothesis commit_hash and compare to stored value.

    Returns (ok, violations). Detects post-commitment tampering of any field.
    """
    if not db_path.exists():
        return False, [f"Ledger not found: {db_path}"]

    violations: list[str] = []

    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM hypotheses ORDER BY id ASC").fetchall()

    for row in rows:
        expected = _compute_commit_hash(
            row["run_id"],
            row["committed_at"],
            row["rationale"],
            row["direction"],
            row["predicted_bpb"],
        )
        if expected != row["commit_hash"]:
            violations.append(
                f"HYPOTHESIS TAMPERED run_id={row['run_id']} hyp_id={row['id']}\n"
                f"  expected {expected[:16]}…\n"
                f"  stored   {row['commit_hash'][:16]}…"
            )

    return len(violations) == 0, violations


def list_hypotheses(db_path: Path) -> list[HypothesisRecord]:
    """Return all hypothesis records in insertion order."""
    if not db_path.exists():
        return []

    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM hypotheses ORDER BY id ASC").fetchall()

    return [
        HypothesisRecord(
            id=r["id"],
            run_id=r["run_id"],
            committed_at=r["committed_at"],
            rationale=r["rationale"],
            direction=r["direction"],
            predicted_bpb=r["predicted_bpb"],
            commit_hash=r["commit_hash"],
        )
        for r in rows
    ]
