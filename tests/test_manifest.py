"""
Tests for trust/manifest.py — HMAC-signed SHA-256 manifest layer.

Each test targets a specific threat the manifest layer is designed to catch.
"""

import json
import pytest
from pathlib import Path

from trust.manifest import create, verify, ManifestError


@pytest.fixture
def ws(tmp_path):
    """Minimal workspace: one protected file, key path, manifest path."""
    protected = tmp_path / "prepare.py"
    protected.write_text("# fixed eval code — do not modify\n")
    return {
        "protected": protected,
        "key_file": tmp_path / ".trust_key",
        "manifest_file": tmp_path / ".trust_manifest.json",
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_create_and_verify_clean(ws):
    """A freshly created manifest verifies without violations."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert ok
    assert violations == []


def test_key_file_created_with_restricted_permissions(ws):
    """Key file is written with mode 0o600 (owner read/write only)."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    mode = ws["key_file"].stat().st_mode & 0o777
    assert mode == 0o600


def test_existing_key_reused(ws):
    """Running init twice with the same key file produces a consistent manifest."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    first_hmac = json.loads(ws["manifest_file"].read_text())["hmac"]

    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    second_hmac = json.loads(ws["manifest_file"].read_text())["hmac"]

    assert first_hmac == second_hmac


# ---------------------------------------------------------------------------
# Threat: agent modifies the protected file
# ---------------------------------------------------------------------------

def test_detect_file_tampering(ws):
    """Detects when a protected file has been modified after manifest creation."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    ws["protected"].write_text("# tampered — agent injected fake eval\n")

    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert any("TAMPERED" in v for v in violations)


def test_detect_missing_file(ws):
    """Detects when a protected file has been deleted."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    ws["protected"].unlink()

    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert any("MISSING" in v for v in violations)


# ---------------------------------------------------------------------------
# Threat: agent modifies the manifest to match tampered files
# ---------------------------------------------------------------------------

def test_detect_manifest_hash_forgery(ws):
    """
    Detects when an agent updates the file hash in the manifest to cover
    its tracks — the HMAC will no longer match.
    """
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    ws["protected"].write_text("# tampered\n")

    # Agent tries to patch the manifest hash to match the new file
    data = json.loads(ws["manifest_file"].read_text())
    import hashlib
    fake_hash = hashlib.sha256(b"# tampered\n").hexdigest()
    data["files"][str(ws["protected"])] = fake_hash
    ws["manifest_file"].write_text(json.dumps(data))

    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert any("HMAC INVALID" in v for v in violations)


def test_detect_manifest_hmac_forgery(ws):
    """
    Detects when an agent replaces the HMAC with an arbitrary value.
    """
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])

    data = json.loads(ws["manifest_file"].read_text())
    data["hmac"] = "a" * 64  # fake signature
    ws["manifest_file"].write_text(json.dumps(data))

    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert any("HMAC INVALID" in v for v in violations)


# ---------------------------------------------------------------------------
# Error conditions
# ---------------------------------------------------------------------------

def test_missing_manifest_returns_violation(ws):
    """verify() returns a violation (not an exception) when manifest is absent."""
    ws["key_file"].write_bytes(b"\x00" * 32)
    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert len(violations) == 1


def test_missing_key_raises(ws):
    """verify() raises ManifestError when the key file does not exist."""
    create([ws["protected"]], ws["key_file"], ws["manifest_file"])
    ws["key_file"].unlink()

    with pytest.raises(ManifestError, match="Key file not found"):
        verify(ws["key_file"], ws["manifest_file"])


def test_init_missing_protected_file_raises(ws):
    """create() raises ManifestError when a listed file does not exist."""
    nonexistent = ws["protected"].parent / "ghost.py"
    with pytest.raises(ManifestError, match="not found"):
        create([nonexistent], ws["key_file"], ws["manifest_file"])


def test_corrupted_manifest_json(ws):
    """verify() returns a violation when the manifest file is not valid JSON."""
    ws["key_file"].write_bytes(b"\x00" * 32)
    ws["manifest_file"].write_text("not json {{{")

    ok, violations = verify(ws["key_file"], ws["manifest_file"])
    assert not ok
    assert any("not valid JSON" in v for v in violations)
