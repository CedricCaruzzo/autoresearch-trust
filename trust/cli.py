"""
trust CLI — entry point for all integrity commands.

Commands:
    init    Create a signed manifest for this project's protected files.
    verify  Re-check the manifest; exit non-zero if anything changed.
    run     Wrap one agent experiment with full integrity checks.
    audit   Run statistical analysis across all logged runs.
"""

import argparse
import sys


def cmd_init(args: argparse.Namespace) -> int:
    from trust.manifest import create, ManifestError
    from pathlib import Path

    try:
        create(
            files=[Path(f) for f in args.protect],
            key_file=Path(args.key_file),
            manifest_file=Path(args.manifest),
        )
    except ManifestError as exc:
        print(f"[trust] ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from trust.manifest import verify, ManifestError
    from pathlib import Path

    try:
        ok, violations = verify(
            key_file=Path(args.key_file),
            manifest_file=Path(args.manifest),
        )
    except ManifestError as exc:
        print(f"[trust] ERROR: {exc}", file=sys.stderr)
        return 1

    if ok:
        print("[trust] OK — all protected files match the manifest.")
        return 0

    print("[trust] INTEGRITY VIOLATION DETECTED:", file=sys.stderr)
    for v in violations:
        print(f"  {v}", file=sys.stderr)
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    import os
    import subprocess
    from pathlib import Path
    from trust.manifest import verify, ManifestError
    from trust.ledger import open_run, close_run, LedgerError
    from trust.hypothesis import commit_hypothesis, HypothesisError
    from trust.evaluator import generate_and_store_nonce, run_isolated_eval, EvaluatorError

    db_path = Path(args.db)
    manifest_path = Path(args.manifest)
    key_file = Path(args.key_file)
    checkpoint_path = Path(args.checkpoint) if args.checkpoint else None
    prepare_path = Path(args.prepare) if args.prepare else Path("prepare.py")

    # 1. Verify manifest before allowing the agent to run
    try:
        ok, violations = verify(key_file=key_file, manifest_file=manifest_path)
    except ManifestError as exc:
        print(f"[trust] ERROR: {exc}", file=sys.stderr)
        return 1

    if not ok:
        print("[trust] BLOCKED — manifest integrity check failed:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print("[trust] The agent will not run until protected files are restored.", file=sys.stderr)
        return 1

    print("[trust] Manifest OK.")

    # 2. Open a ledger entry BEFORE the agent runs (it's on the record even on crash)
    try:
        run_id = open_run(db_path, script=args.script)
    except LedgerError as exc:
        print(f"[trust] ERROR opening ledger entry: {exc}", file=sys.stderr)
        return 1

    print(f"[trust] Ledger entry #{run_id} opened.")

    # 3. Generate eval nonce BEFORE the script runs — provenance anchor
    eval_nonce = generate_and_store_nonce(db_path, run_id, checkpoint_path)
    print(f"[trust] Eval nonce generated: {eval_nonce[:8]}…")

    # 4. Commit hypothesis BEFORE the script runs — must precede execution
    rationale = os.environ.get("TRUST_RATIONALE", "").strip()
    direction = os.environ.get("TRUST_DIRECTION", "").strip()
    predicted_bpb_str = os.environ.get("TRUST_PREDICTED_BPB", "").strip()
    predicted_bpb = float(predicted_bpb_str) if predicted_bpb_str else None

    if not rationale or not direction:
        print(
            "[trust] WARNING — no hypothesis committed (set TRUST_RATIONALE and "
            "TRUST_DIRECTION env vars before running). This run will be flagged by the auditor.",
            file=sys.stderr,
        )
    else:
        try:
            hyp_id = commit_hypothesis(
                db_path, run_id,
                rationale=rationale,
                direction=direction,
                predicted_bpb=predicted_bpb,
            )
            print(f"[trust] Hypothesis #{hyp_id} committed — direction={direction}.")
        except HypothesisError as exc:
            print(f"[trust] ERROR committing hypothesis: {exc}", file=sys.stderr)
            return 1

    # 5. Execute the agent script
    result = subprocess.run([sys.executable, args.script])
    exit_code = result.returncode

    # 6. Close the ledger entry — status is 'crash' if the script failed
    val_bpb = None
    if exit_code != 0:
        status = "crash"
        description = f"script exited with code {exit_code}"
        print(f"[trust] Script exited with code {exit_code}. Logged as crash.", file=sys.stderr)
    else:
        status = os.environ.get("TRUST_STATUS", "keep").strip()
        description = os.environ.get("TRUST_DESCRIPTION", "").strip()
        if status not in ("keep", "discard"):
            status = "keep"

        # If a checkpoint path was given, use the isolated evaluator.
        # Otherwise fall back to self-reported TRUST_VAL_BPB (with a warning).
        if checkpoint_path and checkpoint_path.exists():
            try:
                eval_result = run_isolated_eval(
                    db_path, run_id, checkpoint_path, prepare_path
                )
                val_bpb = eval_result.val_bpb
                print(f"[trust] Isolated eval complete — val_bpb={val_bpb:.6f} (nonce={eval_result.nonce[:8]}…)")
            except EvaluatorError as exc:
                print(f"[trust] WARNING — isolated eval failed: {exc}", file=sys.stderr)
                print("[trust] Falling back to TRUST_VAL_BPB env var.", file=sys.stderr)
                val_bpb_str = os.environ.get("TRUST_VAL_BPB", "").strip()
                val_bpb = float(val_bpb_str) if val_bpb_str else None
        else:
            val_bpb_str = os.environ.get("TRUST_VAL_BPB", "").strip()
            val_bpb = float(val_bpb_str) if val_bpb_str else None
            if val_bpb is not None:
                print(
                    "[trust] NOTE — val_bpb is self-reported (no --checkpoint given). "
                    "Use --checkpoint for isolated evaluation.",
                    file=sys.stderr,
                )

    try:
        close_run(db_path, run_id, val_bpb=val_bpb, status=status, description=description)
    except LedgerError as exc:
        print(f"[trust] ERROR closing ledger entry: {exc}", file=sys.stderr)
        return 1

    print(f"[trust] Ledger entry #{run_id} closed — status={status}, val_bpb={val_bpb}.")

    # 7. Re-verify manifest after the agent ran (catches in-run tampering)
    try:
        ok, violations = verify(key_file=key_file, manifest_file=manifest_path)
    except ManifestError as exc:
        print(f"[trust] POST-RUN manifest check error: {exc}", file=sys.stderr)
        return 1

    if not ok:
        print("[trust] WARNING — manifest violated DURING the run:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print("[trust] Post-run manifest OK.")
    return exit_code


def cmd_audit(args: argparse.Namespace) -> int:
    from pathlib import Path
    from trust.auditor import audit, ANOMALY, WARNING, INFO

    db_path = Path(args.db)
    report = audit(db_path)

    # Severity order for display
    order = {ANOMALY: 0, WARNING: 1, INFO: 2}
    sorted_findings = sorted(report.findings, key=lambda f: order[f.severity])

    labels = {ANOMALY: "ANOMALY", WARNING: "WARNING", INFO: "INFO   "}
    for f in sorted_findings:
        prefix = labels[f.severity]
        # indent continuation lines
        msg = f.message.replace("\n", "\n         ")
        print(f"[{prefix}] {f.code}: {msg}")

    print()
    print(f"[trust] Audit complete — {report.summary()}")

    return 1 if report.has_anomalies else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trust",
        description="Cryptographic integrity layer for autonomous ML research agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a signed manifest for protected files.")
    p_init.add_argument(
        "protect",
        nargs="+",
        metavar="FILE",
        help="Files to protect (e.g. prepare.py).",
    )
    p_init.add_argument(
        "--key-file",
        default=".trust_key",
        metavar="PATH",
        help="Path to HMAC key file (created if absent).",
    )
    p_init.add_argument(
        "--manifest",
        default=".trust_manifest.json",
        metavar="PATH",
    )
    p_init.set_defaults(func=cmd_init)

    p_verify = sub.add_parser("verify", help="Verify manifest; exit 1 if tampered.")
    p_verify.add_argument("--manifest", default=".trust_manifest.json", metavar="PATH")
    p_verify.add_argument("--key-file", default=".trust_key", metavar="PATH")
    p_verify.set_defaults(func=cmd_verify)

    p_run = sub.add_parser("run", help="Run one agent experiment with integrity checks.")
    p_run.add_argument("script", help="Agent script to execute.")
    p_run.add_argument("--manifest", default=".trust_manifest.json", metavar="PATH")
    p_run.add_argument("--key-file", default=".trust_key", metavar="PATH")
    p_run.add_argument("--db", default="trust.db", metavar="PATH")
    p_run.add_argument(
        "--checkpoint", default=None, metavar="PATH",
        help="Model checkpoint saved by the agent script. "
             "If provided, evaluation runs in an isolated subprocess.",
    )
    p_run.add_argument(
        "--prepare", default="prepare.py", metavar="PATH",
        help="Path to prepare.py (default: ./prepare.py).",
    )
    p_run.set_defaults(func=cmd_run)

    p_audit = sub.add_parser("audit", help="Statistical audit across all logged runs.")
    p_audit.add_argument("--db", default="trust.db", metavar="PATH")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))
