# -*- coding: utf-8 -*-
"""Unit tests for PasswordVault v3.6.0 improvements (Issue #9)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vault.constants import (
    EXPORT_MAGIC_GZ,
    VAULT_SCHEMA_VERSION,
)
from vault.crypto import (
    benchmark_argon2,
    decrypt_any_backup,
    new_session,
    verify_vault_integrity,
)
from vault.exporters import export_vault
from vault.features.generator import (
    generate_random_password,
    generate_random_token,
)
from vault.features.health import (
    check_entry_rotation_needed,
    collect_health,
    find_matches_regex,
    is_common_password,
)
from vault.importers import import_keepass_xml
from vault.models import validate_vault_schema_detailed
from vault.ui import prompt_with_timeout


def test_benchmark_argon2():
    results = benchmark_argon2()
    assert isinstance(results, list)
    assert len(results) == 3
    for r in results:
        assert "name" in r
        assert "time_cost" in r
        assert "memory_mb" in r
        assert "lanes" in r
        assert "elapsed_ms" in r
        assert r["elapsed_ms"] >= 0


def test_compressed_export_and_decrypt(tmp_path: Path):
    session = new_session("MasterPass123!Secure")
    vault_data = {
        "test-compressed": {
            "type": "password",
            "username": "alice",
            "password": "SecretPassword123!",
            "url": "https://example.com",
        }
    }
    out_file = tmp_path / "backup.pvex.gz"
    res_path = export_vault(session, vault_data, out_file, compress=True)
    assert res_path.is_file()

    raw_bytes = res_path.read_bytes()
    assert raw_bytes.startswith(EXPORT_MAGIC_GZ)

    ok_flag, msg = verify_vault_integrity(raw_bytes)
    assert ok_flag is True

    decrypted = decrypt_any_backup(raw_bytes, "MasterPass123!Secure")
    assert "test-compressed" in decrypted
    assert decrypted["test-compressed"]["password"] == "SecretPassword123!"


def test_is_common_password_and_health_integration():
    assert is_common_password("password") is True
    assert is_common_password("123456") is True
    assert is_common_password("admin") is True
    assert is_common_password("Xy9#mK!7901_veryunlikely") is False
    assert is_common_password("") is False

    vault = {
        "insecure_service": {
            "type": "password",
            "password": "password",
            "username": "root",
        },
        "secure_service": {
            "type": "password",
            "password": "StrongPassword-2026!#",
            "username": "user",
        },
    }
    health = collect_health(vault)
    assert "insecure_service" in health["common"]
    assert "secure_service" not in health["common"]


def test_find_matches_regex():
    vault = {
        "aws-prod-database": {"username": "admin", "url": "https://aws.amazon.com", "notes": "rds cluster"},
        "azure-dev-db": {"username": "developer", "url": "https://portal.azure.com", "notes": "dev sql"},
        "github-personal": {"username": "shashank", "url": "https://github.com", "notes": "git auth"},
    }
    matches, err = find_matches_regex(vault, r"prod|dev")
    assert err is None
    assert matches == ["aws-prod-database", "azure-dev-db"]

    matches_note, err = find_matches_regex(vault, r"cluster")
    assert err is None
    assert matches_note == ["aws-prod-database"]

    invalid_matches, err = find_matches_regex(vault, r"[unclosed")
    assert err is not None
    assert invalid_matches == []


def test_check_entry_rotation_needed():
    entry_old = {"created": "2020-01-01", "password": "OldPassword1!"}
    needs_rot, age = check_entry_rotation_needed(entry_old, threshold_days=90)
    assert needs_rot is True
    assert age > 365

    entry_recent = {"created": "2099-01-01", "password": "FuturePassword1!"}
    needs_rot2, age2 = check_entry_rotation_needed(entry_recent, threshold_days=90)
    assert needs_rot2 is False

    entry_no_date = {"password": "NoDatePassword!"}
    needs_rot3, age3 = check_entry_rotation_needed(entry_no_date)
    assert needs_rot3 is False
    assert age3 == 0


def test_generate_random_token():
    hex_token = generate_random_token("hex", length=16)
    assert len(hex_token) == 16
    assert all(c in "0123456789abcdef" for c in hex_token)

    b64_token = generate_random_token("base64", length=24)
    assert len(b64_token) == 24

    uuid_token = generate_random_token("uuid")
    assert len(uuid_token) == 36
    assert uuid_token.count("-") == 4

    alpha_token = generate_random_token("alphanumeric", length=30)
    assert len(alpha_token) == 30
    assert alpha_token.isalnum()

    with pytest.raises(ValueError):
        generate_random_token("hex", length=4)
    with pytest.raises(ValueError):
        generate_random_token("unsupported_type")


def test_generate_random_password_include_exclude():
    # Exclude all digits
    pwd_no_digits = generate_random_password(length=20, symbols=False, exclude_chars="0123456789")
    assert not any(c.isdigit() for c in pwd_no_digits)

    # Force include unique punctuation
    pwd_with_include = generate_random_password(length=20, include_chars="@$")
    assert any(c in "@$" for c in pwd_with_include)

    # Extreme exclusions
    with pytest.raises(ValueError):
        generate_random_password(
            length=10,
            symbols=True,
            exclude_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        )


def test_keepass_xml_import(tmp_path: Path):
    xml_content = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Root</Name>
      <Entry>
        <String>
          <Key>Title</Key>
          <Value>Imported Service</Value>
        </String>
        <String>
          <Key>UserName</Key>
          <Value>kp_user</Value>
        </String>
        <String>
          <Key>Password</Key>
          <Value>kp_secret_pass_123!</Value>
        </String>
        <String>
          <Key>URL</Key>
          <Value>https://keepass.info</Value>
        </String>
        <String>
          <Key>Notes</Key>
          <Value>migrated from keepass</Value>
        </String>
        <String>
          <Key>CustomPIN</Key>
          <Value>9876</Value>
        </String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>
"""
    xml_path = tmp_path / "keepass_export.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    vault: dict = {}
    session = new_session("MasterPass123!Secure")
    added, skipped = import_keepass_xml(vault, session, xml_path)
    assert added == 1
    assert skipped == 0
    assert "Imported Service" in vault
    entry = vault["Imported Service"]
    assert entry["username"] == "kp_user"
    assert entry["password"] == "kp_secret_pass_123!"
    assert entry["url"] == "https://keepass.info"
    assert entry["custom_fields"]["CustomPIN"] == "9876"


def test_validate_vault_schema_detailed():
    valid_data = {
        "schema_version": VAULT_SCHEMA_VERSION,
        "entries": {
            "service_a": {
                "type": "password",
                "username": "user_a",
                "password": "Password123!",
                "created": "2026-01-01",
                "tags": ["prod", "cloud"],
            }
        },
    }
    is_valid, errors = validate_vault_schema_detailed(valid_data)
    assert is_valid is True
    assert errors == []

    invalid_data = {
        "schema_version": 999,
        "entries": {
            "bad_service": {
                "type": "unknown_type",
                "created": "invalid-date",
                "tags": "not_a_list",
            }
        },
    }
    is_valid, errors = validate_vault_schema_detailed(invalid_data)
    assert is_valid is False
    assert len(errors) >= 3


def test_prompt_with_timeout_non_interactive():
    # Calling prompt_with_timeout with 0 seconds falls back safely to default
    val = prompt_with_timeout("Test prompt", timeout_seconds=0, default="fallback_val")
    assert val == "fallback_val"


def test_cli_benchmark(capsys):
    from vault.cli import main
    rc = main(["benchmark"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Argon2id Hardware Performance Benchmark" in captured.out

    rc_json = main(["benchmark", "--json"])
    assert rc_json == 0
    captured_json = capsys.readouterr()
    data = json.loads(captured_json.out)
    assert len(data) == 3


def test_cli_gen_token(capsys):
    from vault.cli import main
    rc = main(["gen", "--token", "hex", "--length", "16", "--show"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 16
    assert all(c in "0123456789abcdef" for c in out)


def test_cli_gen_custom_chars(capsys):
    from vault.cli import main
    rc = main(["gen", "--length", "24", "--include", "#!", "--exclude", "0123456789", "--show"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 24
    assert any(c in "#!" for c in out)
    assert not any(c.isdigit() for c in out)

