# -*- coding: utf-8 -*-
"""Comprehensive tests for new security, crypto, TOTP, HIBP, and integration features."""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vault as v
from vault.constants import (
    VAULT_MAGIC_V3,
)
from vault.crypto import (
    decrypt_container,
    derive_argon2_key,
    is_dpapi_available,
    pack_container,
    save_quick_unlock,
    try_quick_unlock,
    zero_buffer,
)
from vault.features.emergency import generate_emergency_kit
from vault.features.generator import (
    AMBIGUOUS_CHARS,
    generate_passphrase,
    generate_random_password,
)
from vault.features.totp import clean_base32_secret, generate_totp
from vault.importers import import_bitwarden_json
from vault.integrations import get_completion_script, handle_git_credential
from vault.models import (
    entry_custom_fields,
    entry_is_favorite,
    entry_tags,
    validate_entry,
)
from vault.storage import (
    check_lockout,
    file_lock,
    record_failure,
    shred_file,
    take_snapshot,
)


# ---------------------------------------------------------------------------
# Test 1: Argon2id KDF & AES-256-GCM AEAD Container (Improvements #2, #3)
# ---------------------------------------------------------------------------
def test_argon2id_derivation_and_aead_roundtrip():
    salt = os.urandom(16)
    key = derive_argon2_key("super-secret-passphrase", salt, iterations=2, memory_cost=1024, lanes=2)
    assert len(key) == 32

    session = v.new_session("master-passphrase-123")
    assert session.kdf_type == "argon2"
    assert session.raw_key is not None

    vault_data = {
        "TestEntry": {
            "type": "password",
            "username": "tester",
            "password": "complex_password_1!",
            "tags": ["personal", "test"],
            "favorite": True,
        }
    }
    container = pack_container(session, vault_data)
    assert container.startswith(VAULT_MAGIC_V3)

    restored_session, restored_vault = decrypt_container(container, "master-passphrase-123")
    assert restored_vault == vault_data
    assert restored_session.salt == session.salt


def test_aead_aad_tamper_detection():
    session = v.new_session("secure-password")
    original = {"Site": {"type": "password", "username": "u", "password": "p"}}
    container = bytearray(pack_container(session, original))

    # Tamper with header/salt bytes
    container[10] ^= 0xFF

    with pytest.raises(InvalidToken):
        decrypt_container(bytes(container), "secure-password")


# ---------------------------------------------------------------------------
# Test 2: Sensitive Memory Zeroing (Improvement #5)
# ---------------------------------------------------------------------------
def test_sensitive_memory_zeroing():
    buf = bytearray(b"very_sensitive_key_material_1234")
    assert any(b != 0 for b in buf)
    zero_buffer(buf)
    assert all(b == 0 for b in buf)


# ---------------------------------------------------------------------------
# Test 3: Tamper-Resistant Rate Limiting (Improvement #6)
# ---------------------------------------------------------------------------
def test_tamper_resistant_rate_limiting(tmp_path, monkeypatch):
    attempts_file = tmp_path / "attempts.json"
    monkeypatch.setattr(v.storage, "ATTEMPTS_FILE", attempts_file)

    # Clean state
    locked, rem = check_lockout()
    assert not locked

    # Record 3 failures
    for _ in range(3):
        record_failure()

    locked, rem = check_lockout()
    assert locked
    assert rem > 0

    # Tamper with count in attempts.json (e.g. set count to 0)
    data = json.loads(attempts_file.read_text(encoding="utf-8"))
    data["count"] = 0
    attempts_file.write_text(json.dumps(data), encoding="utf-8")

    # Tamper detection should flag invalid HMAC signature
    locked, rem = check_lockout()
    assert locked  # Still locked because HMAC was violated!


# ---------------------------------------------------------------------------
# Test 4: TOTP (RFC 6238) Generator (Improvement #9)
# ---------------------------------------------------------------------------
def test_totp_rfc6238_standard_test_vector():
    # RFC 6238 standard base32 seed: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ (12345678901234567890)
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    # Epoch 59s: count=1 -> 287082
    code, rem = generate_totp(seed, interval=30, digits=6, for_time=59)
    assert code == "287082"
    assert rem == 1

    # Epoch 1111111109s
    code, _ = generate_totp(seed, interval=30, digits=6, for_time=1111111109)
    assert code == "081804"


def test_clean_base32_secret():
    cleaned = clean_base32_secret("jbsw y3dp-ehpk 3pxp")
    assert len(cleaned) == 10


# ---------------------------------------------------------------------------
# Test 5: Entry History, Custom Fields, Tags, Favorites (Improvements #11-#14)
# ---------------------------------------------------------------------------
def test_advanced_entry_model_properties():
    entry = {
        "type": "password",
        "username": "alice",
        "password": "pwd",
        "tags": ["finance", "crypto"],
        "favorite": True,
        "history": [{"secret": "old_pwd", "changed_at": "2026-01-01"}],
        "custom_fields": {"PIN": "4321", "Recovery": "secret_phrase"},
    }
    validated = validate_entry(entry, "TestAccount")
    assert entry_tags(validated) == ["finance", "crypto"]
    assert entry_is_favorite(validated) is True
    assert entry_custom_fields(validated) == {"PIN": "4321", "Recovery": "secret_phrase"}


# ---------------------------------------------------------------------------
# Test 6: Emergency Recovery Kit (Improvement #16)
# ---------------------------------------------------------------------------
def test_emergency_recovery_kit_generation(tmp_path, monkeypatch):
    monkeypatch.setattr(v.constants, "APP_DIR", tmp_path)
    monkeypatch.setattr(v.features.emergency, "APP_DIR", tmp_path)

    session = v.new_session("my-master-password")
    kit_path = generate_emergency_kit(session, owner_name="Alice")

    assert kit_path.is_file()
    content = kit_path.read_text(encoding="utf-8")
    assert "Secure Password Vault · Emergency Kit" in content
    assert "Alice" in content
    assert session.salt.hex() in content


# ---------------------------------------------------------------------------
# Test 7: Multi-Process File Locking (Improvement #18)
# ---------------------------------------------------------------------------
def test_file_lock_prevents_concurrent_access(tmp_path):
    lock_file = tmp_path / "vault.enc"
    with file_lock(lock_file):
        # Second acquire should timeout
        with pytest.raises(TimeoutError):
            with file_lock(lock_file, timeout=0.2):
                pass


# ---------------------------------------------------------------------------
# Test 8: Rolling Snapshots (Improvement #19)
# ---------------------------------------------------------------------------
def test_rolling_snapshots(tmp_path, monkeypatch):
    monkeypatch.setattr(v.storage, "SNAPSHOTS_DIR", tmp_path / "snaps")
    vault_file = tmp_path / "vault.enc"
    vault_file.write_bytes(b"initial data")

    snap1 = take_snapshot(vault_file, max_snapshots=3)
    assert snap1 is not None and snap1.is_file()
    assert snap1.read_bytes() == b"initial data"


# ---------------------------------------------------------------------------
# Test 9: Windows DPAPI Quick PIN Unlock (Improvement #21)
# ---------------------------------------------------------------------------
def test_dpapi_quick_unlock_on_windows(tmp_path, monkeypatch):
    if not is_dpapi_available():
        pytest.skip("DPAPI is only supported on Windows")

    unlock_file = tmp_path / "quick_unlock.dat"
    monkeypatch.setattr(v.crypto, "QUICK_UNLOCK_FILE", unlock_file)

    session = v.new_session("master-password-dpapi")
    saved = save_quick_unlock(session, pin="123456", timeout_seconds=300)
    assert saved is True
    assert unlock_file.is_file()

    # Successful quick unlock with PIN
    restored = try_quick_unlock("123456")
    assert restored is not None
    assert restored.raw_key == session.raw_key

    # Failed quick unlock with wrong PIN
    bad = try_quick_unlock("999999")
    assert bad is None


# ---------------------------------------------------------------------------
# Test 10: Multi-Shell Completion Scripts (Improvement #22)
# ---------------------------------------------------------------------------
def test_multi_shell_completions():
    for sh in ("powershell", "bash", "zsh", "fish"):
        script = get_completion_script(sh)
        assert len(script) > 20
        assert "vault" in script


# ---------------------------------------------------------------------------
# Test 11: Git Credential Helper (Improvement #23)
# ---------------------------------------------------------------------------
def test_git_credential_helper(capsys, monkeypatch):
    vault = {
        "github.com": {
            "type": "password",
            "username": "gituser",
            "password": "gitpassword123",
            "url": "https://github.com",
        }
    }
    session = v.new_session("pwd")
    monkeypatch.setattr("sys.stdin", io.StringIO("protocol=https\nhost=github.com\n\n"))

    handle_git_credential("get", vault, session)
    out = capsys.readouterr().out
    assert "username=gituser" in out
    assert "password=gitpassword123" in out


# ---------------------------------------------------------------------------
# Test 12: Dotenv Export (Improvement #24)
# ---------------------------------------------------------------------------
def test_export_dotenv(tmp_path):
    vault = {
        "Stripe Key": {"type": "password", "password": "sk_test_123", "env": "STRIPE_KEY"},
        "OpenAI": {"type": "password", "password": "sk_proj_456"},
    }
    env_file = tmp_path / ".env"
    count = v.export_dotenv(vault, env_file)
    assert count == 2
    content = env_file.read_text(encoding="utf-8")
    assert 'STRIPE_KEY="sk_test_123"' in content
    assert 'OPENAI="sk_proj_456"' in content


# ---------------------------------------------------------------------------
# Test 13: Bitwarden JSON Import (Improvement #27)
# ---------------------------------------------------------------------------
def test_bitwarden_json_import(tmp_path, monkeypatch):
    bw_json = tmp_path / "bitwarden_export.json"
    bw_data = {
        "encrypted": False,
        "items": [
            {
                "name": "Twitter",
                "type": 1,
                "login": {
                    "username": "tweet_user",
                    "password": "tweet_password",
                    "uris": [{"uri": "https://twitter.com"}],
                    "totp": "JBSWY3DPEHPK3PXP",
                },
                "notes": "My Twitter Account",
                "fields": [{"name": "RecoveryCode", "value": "xyz-123"}],
            }
        ],
    }
    bw_json.write_text(json.dumps(bw_data), encoding="utf-8")

    vault: dict = {}
    session = v.new_session("pwd")
    monkeypatch.setattr(v.crypto, "save_vault", lambda _sess, _v: None)

    added, skipped = import_bitwarden_json(vault, session, bw_json)
    assert added == 1
    assert skipped == 0
    assert "Twitter" in vault
    assert vault["Twitter"]["username"] == "tweet_user"
    assert vault["Twitter"]["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert vault["Twitter"]["custom_fields"]["RecoveryCode"] == "xyz-123"


# ---------------------------------------------------------------------------
# Test 14: Secure File Shredding (Improvement #30)
# ---------------------------------------------------------------------------
def test_secure_shred_file(tmp_path):
    f = tmp_path / "sensitive.txt"
    f.write_text("very sensitive plain text credentials", encoding="utf-8")
    assert f.is_file()
    assert shred_file(f, passes=2) is True
    assert not f.exists()


# ---------------------------------------------------------------------------
# Test 15: Generator Ambiguity Exclusion & EFF Passphrase (Improvement #34)
# ---------------------------------------------------------------------------
def test_generator_ambiguity_and_eff_passphrase():
    for _ in range(10):
        pwd = generate_random_password(length=24, symbols=True, exclude_ambiguous=True)
        assert len(pwd) == 24
        assert not any(c in AMBIGUOUS_CHARS for c in pwd)

    phrase = generate_passphrase(words=5, sep="-")
    parts = phrase.split("-")
    assert len(parts) == 5
    assert all(len(p) >= 3 for p in parts)
