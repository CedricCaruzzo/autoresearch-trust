"""
Ledger layer — append-only Merkle-chained run log.

How it works
------------
Every experiment run is recorded in a SQLite database as a two-phase entry:

1. ``open_run()``  — called BEFORE the agent script runs. Records a timestamp,
   a random nonce, and the hash of the previous entry. Returns a run_id.

2. ``close_run()`` — called AFTER the agent script exits. Records the result
   (val_bpb, status, description) and seals the entry with a chain hash.

Each entry's chain_hash is SHA-256(prev_chain_hash + entry_fields), so any
deletion or modification of a past entry breaks the chain from that point
forward. ``verify_chain()`` detects this in O(n) time.

Limitation (same as the manifest layer)
----------------------------------------
The agent runs as the same OS user and could delete trust.db entirely or
replace it with a new one starting from a clean chain. That event is visible:
a missing or reset ledger mid-run is itself a signal. This is a demonstration
of the concept, not a hardened append-only store. A production version would
write chain anchors to an external append-only service (e.g. a transparency log
or a blockchain) that the agent cannot reach.
"""

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_at     REAL    NOT NULL,          -- unix timestamp, set on open
    closed_at     REAL,                      -- unix timestamp, set on close
    nonce         TEXT    NOT NULL,          -- random hex, prevents replay
    script        TEXT    NOT NULL,          -- agent script path
    val_bpb       REAL,                      -- result metric (NULL until closed)
    status        TEXT,                      -- 'keep' | 'discard' | 'crash' | NULL
    description   TEXT,                      -- short experiment description
    chain_hash    TEXT    NOT NULL           -- Merkle link: SHA-256(prev + fields)
);
"""

_GENESIS_HASH = "0" * 64  # anchor for the first entry


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


def _compute_chain_hash(prev_hash: str, fields: dict) -> str:
    """Hash the previous chain hash together with this entry's immutable fields."""
    body = prev_hash + json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def _last_chain_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT chain_hash FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    return row["chain_hash"] if row else _GENESIS_HASH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class RunRecord:
    id: int
    opened_at: float
    closed_at: float | None
    nonce: str
    script: str
    val_bpb: float | None
    status: str | None
    description: str | None
    chain_hash: str


class LedgerError(Exception):
    """Raised when ledger integrity is violated."""


def open_run(db_path: Path, script: str) -> int:
    """
    Open a new run entry BEFORE the agent executes.

    Returns the run_id to pass to ``close_run()``.
    The entry is written immediately — the run is on the record even if the
    process crashes before ``close_run()`` is called.
    """
    nonce = secrets.token_hex(16)
    opened_at = time.time()

    with _connect(db_path) as conn:
        prev_hash = _last_chain_hash(conn)
        fields = {"opened_at": opened_at, "nonce": nonce, "script": script}
        chain_hash = _compute_chain_hash(prev_hash, fields)

        cur = conn.execute(
            "INSERT INTO runs (opened_at, nonce, script, chain_hash) VALUES (?,?,?,?)",
            (opened_at, nonce, script, chain_hash),
        )
        run_id = cur.lastrowid

    return run_id


def close_run(
    db_path: Path,
    run_id: int,
    *,
    val_bpb: float | None,
    status: str,
    description: str,
) -> None:
    """
    Seal a run entry AFTER the agent exits.

    ``status`` must be one of: 'keep', 'discard', 'crash'.
    ``val_bpb`` may be None for crashes.
    """
    if status not in ("keep", "discard", "crash"):
        raise LedgerError(f"Invalid status '{status}'. Must be keep, discard, or crash.")

    closed_at = time.time()

    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise LedgerError(f"Run {run_id} not found in ledger.")
        if row["closed_at"] is not None:
            raise LedgerError(f"Run {run_id} is already closed.")

        conn.execute(
            """UPDATE runs
               SET closed_at=?, val_bpb=?, status=?, description=?
               WHERE id=?""",
            (closed_at, val_bpb, status, description, run_id),
        )


def verify_chain(db_path: Path) -> tuple[bool, list[str]]:
    """
    Walk every entry in insertion order and verify the Merkle chain.

    Returns (ok, violations). An empty violations list means the ledger
    has not been tampered with.
    """
    if not db_path.exists():
        return False, [f"Ledger not found: {db_path}"]

    violations: list[str] = []
    prev_hash = _GENESIS_HASH

    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id ASC").fetchall()

    for row in rows:
        fields = {
            "opened_at": row["opened_at"],
            "nonce": row["nonce"],
            "script": row["script"],
        }
        expected = _compute_chain_hash(prev_hash, fields)
        if expected != row["chain_hash"]:
            violations.append(
                f"CHAIN BROKEN at run {row['id']} "
                f"(opened {row['opened_at']:.0f}, script={row['script']})\n"
                f"  expected {expected[:16]}…\n"
                f"  stored   {row['chain_hash'][:16]}…"
            )
        prev_hash = row["chain_hash"]

    return len(violations) == 0, violations


def list_runs(db_path: Path) -> list[RunRecord]:
    """Return all run records in insertion order."""
    if not db_path.exists():
        return []

    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM runs ORDER BY id ASC").fetchall()

    return [
        RunRecord(
            id=r["id"],
            opened_at=r["opened_at"],
            closed_at=r["closed_at"],
            nonce=r["nonce"],
            script=r["script"],
            val_bpb=r["val_bpb"],
            status=r["status"],
            description=r["description"],
            chain_hash=r["chain_hash"],
        )
        for r in rows
    ]
