"""
Auditor layer — statistical anomaly detection across the full run history.

This layer doesn't protect any single run. It looks at the *pattern* of
runs accumulated in the ledger and asks: does this look like genuine research,
or like an agent gaming the metric?

Findings are classified as:
  INFO     — neutral observations (run counts, coverage stats)
  WARNING  — patterns worth investigating, not conclusive alone
  ANOMALY  — strong signals of gaming or integrity failure

The auditor delegates chain and hypothesis integrity to the lower layers and
adds five statistical checks on top:

  1. Ledger chain integrity       — broken chain = tampered log
  2. Hypothesis integrity         — tampered predictions
  3. Missing hypotheses           — runs with no committed prediction
  4. Unclosed runs                — opened but never closed (silent crashes)
  5. ID gap detection             — non-contiguous IDs = deleted entries
  6. Keep rate                    — suspiciously few discards
  7. Direction accuracy           — prediction vs outcome correlation
  8. BPB improvement consistency  — implausibly smooth improvement curve

On direction accuracy:
  Random guessing gives ~50% accuracy on a binary improve/not-improve split.
  Genuine researchers tend to be right more often than chance.
  An agent gaming the metric will show near-chance accuracy (hypotheses are
  noise) combined with suspiciously good results — that decoupling is the
  primary signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from trust.ledger import list_runs, verify_chain, RunRecord
from trust.hypothesis import list_hypotheses, verify_hypothesis_integrity, HypothesisRecord


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

INFO = "INFO"
WARNING = "WARNING"
ANOMALY = "ANOMALY"


@dataclass
class Finding:
    severity: str   # INFO | WARNING | ANOMALY
    code: str       # short machine-readable identifier
    message: str    # human-readable explanation


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_anomalies(self) -> bool:
        return any(f.severity == ANOMALY for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.severity == WARNING for f in self.findings)

    def add(self, severity: str, code: str, message: str) -> None:
        self.findings.append(Finding(severity=severity, code=code, message=message))

    def summary(self) -> str:
        anomalies = sum(1 for f in self.findings if f.severity == ANOMALY)
        warnings = sum(1 for f in self.findings if f.severity == WARNING)
        infos = sum(1 for f in self.findings if f.severity == INFO)
        return (
            f"{anomalies} anomaly(ies), {warnings} warning(s), {infos} info(s)"
        )


# ---------------------------------------------------------------------------
# Thresholds (documented so researchers can adjust)
# ---------------------------------------------------------------------------

# Keep rate above this with >MIN_RUNS_FOR_STATS runs → WARNING
HIGH_KEEP_RATE_THRESHOLD = 0.85

# Direction accuracy below this → WARNING (random chance on improve/not is ~0.5)
LOW_DIRECTION_ACCURACY_THRESHOLD = 0.45

# Minimum closed runs before statistical checks are meaningful
MIN_RUNS_FOR_STATS = 5

# Maximum fraction of runs allowed to be missing a hypothesis before WARNING
MAX_MISSING_HYPOTHESIS_RATE = 0.20


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _outcome_direction(prev_bpb: float, curr_bpb: float, neutral_band: float = 0.001) -> str:
    """Classify the observed direction of a val_bpb change."""
    delta = curr_bpb - prev_bpb
    if delta < -neutral_band:
        return "improve"
    if delta > neutral_band:
        return "degrade"
    return "neutral"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit(db_path: Path) -> AuditReport:
    """
    Run all audit checks against the ledger at db_path.
    Returns an AuditReport with all findings.
    """
    report = AuditReport()

    if not db_path.exists():
        report.add(ANOMALY, "NO_LEDGER", f"Ledger not found: {db_path}")
        return report

    # ------------------------------------------------------------------ #
    # 1. Ledger chain integrity
    # ------------------------------------------------------------------ #
    chain_ok, chain_violations = verify_chain(db_path)
    if not chain_ok:
        for v in chain_violations:
            report.add(ANOMALY, "CHAIN_BROKEN", v)
    else:
        report.add(INFO, "CHAIN_OK", "Ledger Merkle chain is intact.")

    # ------------------------------------------------------------------ #
    # 2. Hypothesis integrity
    # ------------------------------------------------------------------ #
    hyp_ok, hyp_violations = verify_hypothesis_integrity(db_path)
    if not hyp_ok:
        for v in hyp_violations:
            report.add(ANOMALY, "HYPOTHESIS_TAMPERED", v)
    else:
        report.add(INFO, "HYPOTHESIS_INTEGRITY_OK", "All hypothesis commit hashes verified.")

    # Load raw data for remaining checks
    runs = list_runs(db_path)
    hypotheses = list_hypotheses(db_path)
    hyp_by_run: dict[int, HypothesisRecord] = {h.run_id: h for h in hypotheses}

    total_runs = len(runs)
    report.add(INFO, "RUN_COUNT", f"Total runs in ledger: {total_runs}")

    if total_runs == 0:
        report.add(INFO, "EMPTY_LEDGER", "No runs recorded yet.")
        return report

    # ------------------------------------------------------------------ #
    # 3. Unclosed runs
    # ------------------------------------------------------------------ #
    unclosed = [r for r in runs if r.closed_at is None]
    if unclosed:
        ids = ", ".join(str(r.id) for r in unclosed)
        report.add(
            WARNING, "UNCLOSED_RUNS",
            f"{len(unclosed)} run(s) were opened but never closed (ids: {ids}). "
            "This may indicate silent crashes not properly logged."
        )

    # ------------------------------------------------------------------ #
    # 4. ID gap detection
    # ------------------------------------------------------------------ #
    ids = [r.id for r in runs]
    expected = list(range(ids[0], ids[0] + len(ids)))
    gaps = [e for e in expected if e not in ids]
    if gaps:
        report.add(
            ANOMALY, "ID_GAPS",
            f"Non-contiguous run IDs detected — {len(gaps)} gap(s) at positions {gaps[:10]}. "
            "Entries may have been deleted from the ledger."
        )
    else:
        report.add(INFO, "NO_ID_GAPS", "Run IDs are contiguous — no deletions detected.")

    # ------------------------------------------------------------------ #
    # 5. Missing hypotheses
    # ------------------------------------------------------------------ #
    closed_runs = [r for r in runs if r.closed_at is not None]
    runs_without_hyp = [r for r in closed_runs if r.id not in hyp_by_run]
    if closed_runs:
        missing_rate = len(runs_without_hyp) / len(closed_runs)
        if missing_rate > MAX_MISSING_HYPOTHESIS_RATE:
            report.add(
                WARNING, "MISSING_HYPOTHESES",
                f"{len(runs_without_hyp)}/{len(closed_runs)} closed runs "
                f"({missing_rate:.0%}) have no committed hypothesis. "
                "Genuine researchers should predict before they run."
            )
        else:
            report.add(
                INFO, "HYPOTHESIS_COVERAGE",
                f"Hypothesis coverage: {len(closed_runs) - len(runs_without_hyp)}/{len(closed_runs)} runs."
            )

    # Statistical checks require a minimum number of closed runs
    if len(closed_runs) < MIN_RUNS_FOR_STATS:
        report.add(
            INFO, "INSUFFICIENT_DATA",
            f"Only {len(closed_runs)} closed run(s) — need {MIN_RUNS_FOR_STATS} for statistical checks."
        )
        return report

    # ------------------------------------------------------------------ #
    # 6. Keep rate
    # ------------------------------------------------------------------ #
    kept = [r for r in closed_runs if r.status == "keep"]
    discarded = [r for r in closed_runs if r.status == "discard"]
    crashed = [r for r in closed_runs if r.status == "crash"]
    keep_rate = len(kept) / len(closed_runs)

    report.add(
        INFO, "RUN_BREAKDOWN",
        f"keep={len(kept)}, discard={len(discarded)}, crash={len(crashed)} "
        f"(keep rate {keep_rate:.0%})"
    )

    if keep_rate > HIGH_KEEP_RATE_THRESHOLD and len(discarded) == 0:
        report.add(
            WARNING, "HIGH_KEEP_RATE",
            f"Keep rate is {keep_rate:.0%} with no discards. "
            "Genuine research produces failures. A perfect keep rate may indicate "
            "selective reporting or cherry-picking runs."
        )

    # ------------------------------------------------------------------ #
    # 7. Direction accuracy
    # ------------------------------------------------------------------ #
    # For each closed run that has a hypothesis and a val_bpb, compare the
    # predicted direction to the observed direction against the previous run's bpb.
    scored: list[tuple[str, str]] = []  # (predicted, observed)

    bpb_sequence = [r for r in closed_runs if r.val_bpb is not None]
    for i, run in enumerate(bpb_sequence):
        if run.id not in hyp_by_run:
            continue
        if i == 0:
            continue  # no previous run to compare against
        prev_bpb = bpb_sequence[i - 1].val_bpb
        observed = _outcome_direction(prev_bpb, run.val_bpb)
        predicted = hyp_by_run[run.id].direction
        scored.append((predicted, observed))

    if scored:
        correct = sum(1 for p, o in scored if p == o)
        accuracy = correct / len(scored)
        report.add(
            INFO, "DIRECTION_ACCURACY",
            f"Hypothesis direction accuracy: {correct}/{len(scored)} ({accuracy:.0%}). "
            f"Random chance baseline is ~50% on improve/not-improve."
        )
        if accuracy < LOW_DIRECTION_ACCURACY_THRESHOLD:
            report.add(
                WARNING, "LOW_DIRECTION_ACCURACY",
                f"Direction accuracy ({accuracy:.0%}) is below the random-chance baseline (~50%). "
                "Hypotheses may be noise written after the fact, or the agent is not "
                "reasoning about its changes before running them."
            )

    # ------------------------------------------------------------------ #
    # 8. BPB improvement consistency
    # ------------------------------------------------------------------ #
    # Flag if every single keep run shows improvement over its predecessor —
    # a real research loop produces occasional lateral moves and near-misses.
    kept_with_bpb = [r for r in kept if r.val_bpb is not None]
    if len(kept_with_bpb) >= MIN_RUNS_FOR_STATS:
        bpb_values = [r.val_bpb for r in kept_with_bpb]
        monotone = all(b <= a for a, b in zip(bpb_values, bpb_values[1:]))
        if monotone:
            report.add(
                WARNING, "MONOTONE_IMPROVEMENT",
                f"All {len(kept_with_bpb)} kept runs show strictly monotone val_bpb improvement. "
                "Real research produces occasional plateaus. "
                "This may indicate cherry-picking or metric gaming."
            )

    return report
