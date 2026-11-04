# -*- coding: utf-8 -*-
"""Test suite for the 30 new improvements and security features."""
import pytest
from cryptography.fernet import InvalidToken

from vault.cli import (
    get_master_password,
    main,
)
from vault.clipboard import clear_clipboard_now
from vault.crypto import (
    new_session,
    pack_container,
    pack_encrypted_json,
    unpack_encrypted_json,
    validate_master_password_strength,
    verify_vault_integrity,
    wipe_memory,
)
from vault.exporters import (
    export_csv,
    export_encrypted_json,
)
from vault.features.generator import generate_with_profile
from vault.features.health import (
    calculate_entropy_audit,
    calculate_health_score_breakdown,
    collect_vault_stats,
    find_similar_passwords,
)
from vault.importers import (
    import_csv,
    import_encrypted_json,
)
from vault.models import (
    prune_entry_history,
    set_expiry_relative,
)
from vault.storage import (
    canonicalize_path,
    list_snapshots,
    prune_backups,
    restore_snapshot,
    take_snapshot,
    verify_backup,
)


def test_wipe_memory():
    buf = bytearray(b"supersecretkey12345")
    wipe_memory(buf)
    assert buf == bytearray(len(buf))

    nested = {"key": bytearray(b"nestedsecret"), "list": [bytearray(b"itemsecret")]}
    wipe_memory(nested)
    assert nested["key"] == bytearray(len(b"nestedsecret"))
    assert nested["list"][0] == bytearray(len(b"itemsecret"))


def test_verify_vault_integrity():
    session = new_session("MasterPass123!Secure")
    vault_data = {"test": {"type": "password", "password": "abc"}}
    packed = pack_container(session, vault_data)

    valid, msg = verify_vault_integrity(packed)
    assert valid is True
    assert "Valid V3" in msg

    # Truncated
    invalid_trunc, msg_trunc = verify_vault_integrity(packed[:10])
    assert invalid_trunc is False
    assert "truncated" in msg_trunc.lower()

    # Corrupt magic
    corrupt = b"BADMG" + packed[5:]
    invalid_magic, msg_magic = verify_vault_integrity(corrupt)
    assert invalid_magic is False
    assert "Unrecognized" in msg_magic


def test_encrypted_json_envelope_roundtrip():
    data = {"api_service": {"type": "api_key", "api_key": "sk-1234567890abcdef"}}
    passphrase = "ExportPassphrase999!"
    envelope_str = pack_encrypted_json(data, passphrase)
    assert "passwordvault-encrypted-json" in envelope_str

    unpacked = unpack_encrypted_json(envelope_str, passphrase)
    assert unpacked == data

    with pytest.raises(InvalidToken):
        unpack_encrypted_json(envelope_str, "WrongPassphrase!")


def test_validate_master_password_strength():
    ok1, msg1, ent1 = validate_master_password_strength("short")
    assert ok1 is False
    assert "at least 10" in msg1

    ok2, msg2, ent2 = validate_master_password_strength("aaaaaaaaaaaaaaaaaaaa")
    assert ok2 is False
    assert "repetitive" in msg2

    ok3, msg3, ent3 = validate_master_password_strength("Correct-Horse-Battery-Staple-2026!")
    assert ok3 is True
    assert ent3 >= 50.0


def test_prune_entry_history():
    entry = {
        "type": "password",
        "password": "current",
        "history": [{"password": f"p{i}"} for i in range(15)],
    }
    removed = prune_entry_history(entry, max_history=10)
    assert removed == 5
    assert len(entry["history"]) == 10
    assert entry["history"][-1]["password"] == "p14"


def test_set_expiry_relative():
    entry = {"type": "password", "password": "pass"}
    exp = set_expiry_relative(entry, days=30)
    assert "expires" in entry
    assert entry["expires"] == exp
    assert len(exp.split("-")) == 3


def test_canonicalize_path(tmp_path):
    sub = tmp_path / "testdir"
    sub.mkdir()
    res = canonicalize_path(sub)
    assert res.is_absolute()
    assert res.exists()


def test_generate_with_profile():
    pin = generate_with_profile("pin")
    assert pin.isdigit()
    assert len(pin) == 6

    alpha = generate_with_profile("alphanumeric", length=16)
    assert len(alpha) == 16
    assert alpha.isalnum()

    mem = generate_with_profile("memorable")
    parts = mem.split("-")
    assert len(parts) == 5

    max_p = generate_with_profile("max")
    assert len(max_p) == 32

    with pytest.raises(ValueError):
        generate_with_profile("invalid_profile")


def test_find_similar_passwords():
    vault = {
        "work1": {"type": "password", "password": "CompanySecret2024!"},
        "work2": {"type": "password", "password": "CompanySecret2025!"},
        "unique": {"type": "password", "password": "X9#zK2$mL8@qW5!v"},
    }
    sim = find_similar_passwords(vault, threshold=0.7)
    assert len(sim) >= 1
    assert sim[0][0] in ("work1", "work2")
    assert sim[0][1] in ("work1", "work2")
    assert sim[0][2] >= 70.0


def test_entropy_audit_and_score_breakdown():
    vault = {
        "weak_acc": {"type": "password", "password": "123"},
        "strong_acc": {"type": "password", "password": "T7$vB9!pL4#qX2@kM8"},
    }
    audit = calculate_entropy_audit(vault)
    assert len(audit) == 2
    assert audit[0]["name"] == "weak_acc"
    assert audit[1]["name"] == "strong_acc"
    assert audit[0]["entropy"] < audit[1]["entropy"]

    report = {"total_entries": 2, "weak": [("weak_acc", "Weak")], "duplicates": {}, "expired": [], "expiring": [], "old": [], "breached": []}
    breakdown = calculate_health_score_breakdown(report)
    assert breakdown["score"] < 100
    assert "weak_passwords" in breakdown["deductions"]
    assert breakdown["deductions"]["weak_passwords"] > 0


def test_collect_vault_stats():
    vault = {
        "item1": {"type": "password", "password": "abc", "tags": ["prod"], "favorite": True},
        "item2": {"type": "api_key", "api_key": "xyz", "totp": "JBSWY3DPEHPK3PXP"},
    }
    stats = collect_vault_stats(vault)
    assert stats["total_entries"] == 2
    assert stats["passwords"] == 1
    assert stats["api_keys"] == 1
    assert stats["totp_enabled"] == 1
    assert stats["favorites"] == 1
    assert stats["unique_tags"] == 1


def test_backup_verify_and_pruning(tmp_path):
    session = new_session("BackupPass123!")
    vault_data = {"test": {"type": "password", "password": "secretpass"}}
    backup_file = tmp_path / "test_backup.enc"
    backup_file.write_bytes(pack_container(session, vault_data))

    ok_val, msg, cnt = verify_backup(backup_file, "BackupPass123!")
    assert ok_val is True
    assert cnt == 1

    ok_bad, msg_bad, _ = verify_backup(backup_file, "WrongPassword!")
    assert ok_bad is False

    # Test pruning
    for i in range(5):
        f = tmp_path / f"backup_{i}.enc"
        f.write_text(f"backup {i}")
    removed = prune_backups(tmp_path, max_backups=2, pattern="backup_*.enc")
    assert len(removed) == 3
    remaining = list(tmp_path.glob("backup_*.enc"))
    assert len(remaining) == 2


def test_snapshots(tmp_path):
    target = tmp_path / "vault.enc"
    target.write_bytes(b"initial_state")
    snaps_dir = tmp_path / "snapshots"
    snap1 = take_snapshot(target, snapshots_dir=snaps_dir)
    assert snap1 is not None and snap1.exists()

    snaps = list_snapshots(snaps_dir)
    assert len(snaps) >= 1

    target.write_bytes(b"modified_state")
    restored = restore_snapshot(snaps[0]["path"], vault_path=target)
    assert restored.read_bytes() == b"initial_state"


def test_export_and_import_encrypted_json(tmp_path):
    session = new_session("Pass123!")
    vault_data = {
        "Entry1": {"type": "password", "password": "pwd1", "username": "user1"},
        "Entry2": {"type": "api_key", "api_key": "key2"},
    }
    export_file = tmp_path / "envelope.json"
    export_encrypted_json(vault_data, export_file, "SharedPassphrase!")
    assert export_file.is_file()

    target_vault = {}
    added, skipped = import_encrypted_json(target_vault, session, export_file, "SharedPassphrase!")
    assert added == 2
    assert skipped == 0
    assert "Entry1" in target_vault
    assert "Entry2" in target_vault


def test_export_csv(tmp_path):
    vault_data = {
        "S1": {"type": "password", "password": "p1", "username": "u1", "url": "https://s1.com", "tags": ["work"]},
        "S2": {"type": "api_key", "api_key": "k2", "notes": "api secret"},
    }
    csv_file = tmp_path / "export.csv"
    cnt = export_csv(vault_data, csv_file, delimiter=";")
    assert cnt == 2
    content = csv_file.read_text(encoding="utf-8")
    assert ";" in content
    assert "S1" in content
    assert "S2" in content


def test_extended_csv_aliases(tmp_path):
    csv_content = """Title,Web Site,Email,Password,Comments
GitHub,https://github.com,dev@test.com,Pass123!,Dev account notes
"""
    f = tmp_path / "1password_export.csv"
    f.write_text(csv_content, encoding="utf-8")

    session = new_session("TestPass123!")
    vault = {}
    added = import_csv(vault, session, f)
    assert added == 1
    assert "GitHub" in vault
    assert vault["GitHub"]["username"] == "dev@test.com"
    assert vault["GitHub"]["password"] == "Pass123!"
    assert vault["GitHub"]["notes"] == "Dev account notes"


def test_clear_clipboard_now():
    # Should execute without error
    res = clear_clipboard_now()
    assert isinstance(res, bool)


def test_get_master_password_file(tmp_path, monkeypatch):
    pwd_file = tmp_path / "secret_pass.txt"
    pwd_file.write_text("EnvMasterPassword987!\n", encoding="utf-8")

    monkeypatch.setenv("VAULT_PASSWORD_FILE", str(pwd_file))
    retrieved = get_master_password()
    assert retrieved == "EnvMasterPassword987!"


def test_cli_clip_clear(capsys):
    rc = main(["clip", "--clear"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cleared" in out.lower()


def test_cli_gen_profile(capsys):
    rc = main(["gen", "--profile", "pin", "--show"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 6
    assert out.isdigit()


def test_cli_crud_extensions(tmp_path, monkeypatch, capsys):
    vault_file = tmp_path / "vault.enc"
    session = new_session("MasterPass123!")
    initial_vault = {
        "TestEntry": {
            "type": "password",
            "password": "Password123!",
            "username": "user@test.com",
            "url": "https://service.com",
            "notes": "Initial notes",
            "tags": ["personal"],
            "favorite": False,
        }
    }
    vault_file.write_bytes(pack_container(session, initial_vault))

    monkeypatch.setattr("vault.cli.VAULT_FILE", vault_file)
    monkeypatch.setattr("vault.crypto.VAULT_FILE", vault_file)
    monkeypatch.setattr("vault.storage.VAULT_FILE", vault_file)
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "MasterPass123!")

    # Test stats
    rc_stats = main(["stats"])
    assert rc_stats == 0
    stats_out = capsys.readouterr().out
    assert "Total entries" in stats_out

    # Test audit
    rc_aud = main(["audit", "--entropy"])
    assert rc_aud == 0
    aud_out = capsys.readouterr().out
    assert "Entropy" in aud_out

    # Test clone
    rc_clone = main(["clone", "TestEntry", "TestEntryStaging"])
    assert rc_clone == 0
    assert "Cloned" in capsys.readouterr().out

    # Test rename
    rc_ren = main(["rename", "TestEntryStaging", "TestEntryProd"])
    assert rc_ren == 0
    assert "Renamed" in capsys.readouterr().out

    # Test fav
    rc_fav = main(["fav", "TestEntryProd"])
    assert rc_fav == 0
    assert "favorited" in capsys.readouterr().out.lower()

    # Test notes view and update
    rc_notes_view = main(["notes", "TestEntryProd"])
    assert rc_notes_view == 0
    assert "Initial notes" in capsys.readouterr().out

    rc_notes_set = main(["notes", "TestEntryProd", "--set", "Updated enterprise notes"])
    assert rc_notes_set == 0
    assert "Updated notes" in capsys.readouterr().out

    # Test tag add and list
    rc_tag_add = main(["tag", "add", "production", "TestEntryProd"])
    assert rc_tag_add == 0
    assert "Updated tag" in capsys.readouterr().out

    rc_tag_list = main(["tag", "list"])
    assert rc_tag_list == 0
    assert "production" in capsys.readouterr().out

    # Test get by URL
    rc_get_url = main(["get", "--url", "service.com", "--raw"])
    assert rc_get_url == 0
    assert "Password123!" in capsys.readouterr().out

