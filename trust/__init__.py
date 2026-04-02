"""
autoresearch-trust: cryptographic integrity layer for autonomous ML research agents.

Layers (built incrementally):
    manifest   — HMAC-signed SHA-256 commitment over protected files
    ledger     — append-only Merkle-chained run log
    evaluator  — isolated subprocess eval with per-run nonce
    hypothesis — structured pre-run prediction committed before eval
    auditor    — statistical anomaly detection across runs
"""

__version__ = "0.1.0"
