"""
Manifest layer — HMAC-signed SHA-256 commitment over protected files.

How it works
------------
1. ``create()`` hashes each protected file (SHA-256) and signs the hash
   dictionary with HMAC-SHA-256 using a local secret key.  The result is
   written as a JSON manifest that is committed to the repo.

2. ``verify()`` re-reads the manifest, recomputes the HMAC to check the
   manifest itself hasn't been forged, then re-hashes each file to check
   it hasn't changed since the manifest was created.

Why HMAC and not a plain hash of the manifest?
-----------------------------------------------
A plain hash only proves the file matches the manifest — but an agent with
write access could update both the file AND the manifest together and the
hash would still match.  HMAC requires knowledge of the secret key, which
stays on the researcher's machine and is never committed.  An agent cannot
produce a valid HMAC without the key.

Key storage
-----------
The key file (.trust_key by default) must NEVER be committed to the repo.
It is listed in .gitignore.  The manifest JSON (.trust_manifest.json) IS
committed — it is the public proof.
"""

import hashlib
import hmac as _hmac
import json
import os
import secrets
from pathlib import Path


class ManifestError(Exception):
    """Raised when manifest creation or verification fails."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_key(key_file: Path) -> bytes:
    key = secrets.token_bytes(32)
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return key


def _load_key(key_file: Path) -> bytes:
    if not key_file.exists():
        raise ManifestError(
            f"Key file not found: {key_file}\n"
            "Run 'trust init <files>' to create a manifest and key."
        )
    return key_file.read_bytes()


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _sign(records: dict, key: bytes) -> str:
    """Return HMAC-SHA-256 hex digest of the canonical JSON of records."""
    body = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return _hmac.new(key, body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create(files: list[Path], key_file: Path, manifest_file: Path) -> None:
    """
    Hash each file and write a HMAC-signed manifest.

    Creates the key file if it does not exist.  Overwrites the manifest if
    it already exists (useful when the researcher intentionally updates a
    protected file and wants to re-anchor).
    """
    if key_file.exists():
        key = _load_key(key_file)
        print(f"[trust] Using existing key: {key_file}")
    else:
        key = _generate_key(key_file)
        print(f"[trust] Generated new key:  {key_file}  (never commit this file)")

    records: dict[str, str] = {}
    for f in files:
        if not f.exists():
            raise ManifestError(f"Protected file not found: {f}")
        records[str(f)] = _hash_file(f)
        print(f"[trust] Hashed {f}  ({records[str(f)][:16]}…)")

    manifest = {
        "version": 1,
        "files": records,
        "hmac": _sign(records, key),
    }
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"[trust] Manifest written: {manifest_file}  (commit this file)")


def verify(key_file: Path, manifest_file: Path) -> tuple[bool, list[str]]:
    """
    Verify manifest integrity.

    Returns (ok, violations) where violations is an empty list on success.
    Raises ManifestError if the key file is missing.
    """
    if not manifest_file.exists():
        return False, [f"Manifest file not found: {manifest_file}  (run 'trust init' first)"]

    key = _load_key(key_file)

    try:
        manifest = json.loads(manifest_file.read_text())
    except json.JSONDecodeError as exc:
        return False, [f"Manifest is not valid JSON: {exc}"]

    records: dict = manifest.get("files", {})
    stored_sig: str = manifest.get("hmac", "")

    # 1. Verify the HMAC — detects manifest file tampering or forgery
    expected_sig = _sign(records, key)
    if not _hmac.compare_digest(expected_sig, stored_sig):
        return False, [
            "MANIFEST HMAC INVALID — the manifest file itself has been tampered with "
            "or was not created with this key."
        ]

    # 2. Re-hash each protected file
    violations: list[str] = []
    for path_str, expected_hash in records.items():
        path = Path(path_str)
        if not path.exists():
            violations.append(f"MISSING   {path_str}")
            continue
        actual_hash = _hash_file(path)
        if actual_hash != expected_hash:
            violations.append(
                f"TAMPERED  {path_str}\n"
                f"          expected {expected_hash[:16]}…\n"
                f"          got      {actual_hash[:16]}…"
            )

    return len(violations) == 0, violations
