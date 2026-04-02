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
    print("trust run — not yet implemented (Phase 4)")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    print("trust audit — not yet implemented (Phase 6)")
    return 0


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
    p_run.set_defaults(func=cmd_run)

    p_audit = sub.add_parser("audit", help="Statistical audit across all logged runs.")
    p_audit.add_argument("--db", default="trust.db", metavar="PATH")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))
