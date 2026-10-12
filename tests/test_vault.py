# tests/test_vault.py
import json
import sys
from pathlib import Path

# Make sure the project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import vault as v
import pytest


# ---------------------------------------------------------------------------
# Password strength
# ---------------------------------------------------------------------------
def test_password_score_basic():
    assert v.password_score("") == 0
    assert v.password_score("a") < 3
    assert v.password_score("abcdefgh") == 2          # length only
    assert v.password_score("Abcdefgh") == 3          # + upper
    assert v.password_score("Abcdefg1") == 4          # + digit
    assert v.password_score("Abcdefg1!") >= 5         # + symbol


def test_check_password_strength():
    grade, color = v.check_password_strength("abc")
    assert grade == "Weak"

    grade, _ = v.check_password_strength("Abcdef12")
    assert grade in ("Moderate", "Strong")

    grade, _ = v.check_password_strength("Abcdef12!@#")
    assert grade == "Strong"


def test_strength_line_contains_grade():
    line = v.strength_line("Abcdef12!")
    assert "Strong" in line or "Moderate" in line


# ---------------------------------------------------------------------------
# Password / passphrase generation
# ---------------------------------------------------------------------------
def test_generate_random_password_length_and_classes():
    pw = v.generate_random_password(24)
    assert len(pw) == 24
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in __import__("string").punctuation for c in pw)


def test_generate_random_password_no_symbols():
    pw = v.generate_random_password(16, symbols=False)
    assert len(pw) == 16
    assert not any(c in __import__("string").punctuation for c in pw)


def test_generate_passphrase():
    phrase = v.generate_passphrase(5)
    parts = phrase.split("-")
    assert len(parts) == 5
    assert all(part.isalpha() for part in parts)


def test_generate_passphrase_custom_sep():
    phrase = v.generate_passphrase(4, sep=" ")
    assert len(phrase.split(" ")) == 4


# ---------------------------------------------------------------------------
# Environment variable name helper
# ---------------------------------------------------------------------------
def test_to_env_name():
    assert v.to_env_name("OpenAI - personal") == "OPENAI_PERSONAL"
    assert v.to_env_name("my api key") == "MY_API_KEY"
    assert v.to_env_name("123start") == "_123START"
    assert v.to_env_name("already_GOOD") == "ALREADY_GOOD"
    assert v.to_env_name("") == "SECRET"


# ---------------------------------------------------------------------------
# Fuzzy matching & search
# ---------------------------------------------------------------------------
def test_find_matches_exact():
    data = {
        "OpenAI": {"type": "api_key", "api_key": "sk-1"},
        "Netflix": {"type": "password", "username": "user", "password": "pass"},
    }
    matches, kind = v.find_matches(data, "openai")
    assert matches == ["OpenAI"]
    assert kind == "exact"


def test_find_matches_partial():
    data = {
        "OpenAI - personal": {"type": "api_key", "api_key": "sk-1"},
        "OpenAI - work": {"type": "api_key", "api_key": "sk-2"},
        "Netflix": {"type": "password", "username": "user", "password": "pass"},
    }
    matches, kind = v.find_matches(data, "openai")
    assert "OpenAI - personal" in matches
    assert "OpenAI - work" in matches
    assert kind == "partial"


def test_find_matches_fuzzy():
    data = {
        "OpenAI - personal": {"type": "api_key", "api_key": "sk-1", "notes": "main key"},
        "Netflix": {"type": "password", "username": "user@mail.com", "password": "secret"},
    }
    matches, kind = v.find_matches(data, "opnai")          # typo
    assert "OpenAI - personal" in matches
    assert kind == "similar"


def test_find_matches_in_notes_and_username():
    data = {
        "ServiceA": {"type": "api_key", "api_key": "sk-1", "notes": "used for tavily project"},
        "Netflix": {"type": "password", "username": "john.doe@gmail.com", "password": "secret"},
    }
    # Search inside notes
    matches, kind = v.find_matches(data, "tavily")
    assert "ServiceA" in matches

    # Search inside username
    matches, kind = v.find_matches(data, "john.doe")
    assert "Netflix" in matches


def test_find_matches_empty_term():
    data = {"A": {}, "B": {}}
    matches, kind = v.find_matches(data, "")
    assert set(matches) == {"A", "B"}
    assert kind == "all"


def test_find_matches_no_results():
    data = {"OpenAI": {"type": "api_key", "api_key": "sk-1"}}
    matches, kind = v.find_matches(data, "zzzznonexistent")
    assert matches == []
    assert kind == "none"


# ---------------------------------------------------------------------------
# Duplicate secret detection
# ---------------------------------------------------------------------------
def test_find_duplicate_secret():
    data = {
        "SiteA": {"type": "password", "username": "u1", "password": "samepass"},
        "SiteB": {"type": "password", "username": "u2", "password": "samepass"},
        "SiteC": {"type": "api_key", "api_key": "unique-key"},
    }
    dups = v.find_duplicate_secret(data, "samepass")
    assert set(dups) == {"SiteA", "SiteB"}

    dups = v.find_duplicate_secret(data, "samepass", exclude="SiteA")
    assert dups == ["SiteB"]

    dups = v.find_duplicate_secret(data, "unique-key")
    assert dups == ["SiteC"]

    dups = v.find_duplicate_secret(data, "does-not-exist")
    assert dups == []


# ---------------------------------------------------------------------------
# Entry helpers
# ---------------------------------------------------------------------------
def test_entry_type_and_secret():
    pwd_entry = {"type": "password", "username": "user", "password": "secret123"}
    api_entry = {"type": "api_key", "api_key": "sk-test", "notes": "note"}

    assert v.entry_type(pwd_entry) == "password"
    assert v.entry_type(api_entry) == "api_key"
    assert v.entry_type("legacy-string") == "password"

    assert v.entry_secret(pwd_entry) == "secret123"
    assert v.entry_secret(api_entry) == "sk-test"
    assert v.entry_secret("legacy-string") == "legacy-string"


def test_entry_note():
    pwd_entry = {"type": "password", "username": "john@mail.com", "password": "x"}
    api_entry = {"type": "api_key", "api_key": "sk", "notes": "my note"}

    assert v.entry_note(pwd_entry) == "john@mail.com"
    assert v.entry_note(api_entry) == "my note"
    assert v.entry_note("legacy") == v.G_EMPTY


# ---------------------------------------------------------------------------
# Date / hostname helpers
# ---------------------------------------------------------------------------
def test_hostname_of():
    assert v.hostname_of("https://www.google.com/login") == "google.com"
    assert v.hostname_of("https://github.com") == "github.com"
    assert v.hostname_of("github.com") == "github.com"
    assert v.hostname_of("") == ""
    assert v.hostname_of("not a url") == ""


def test_parse_date():
    assert v.parse_date("2025-12-31") is not None
    assert v.parse_date("") is None
    assert v.parse_date("invalid") is None


# ---------------------------------------------------------------------------
# Environment name regex
# ---------------------------------------------------------------------------
def test_env_name_regex():
    assert v.ENV_NAME_RE.match("OPENAI_API_KEY")
    assert v.ENV_NAME_RE.match("_PRIVATE")
    assert not v.ENV_NAME_RE.match("1INVALID")
    assert not v.ENV_NAME_RE.match("has-dash")
    assert not v.ENV_NAME_RE.match("has space")


# ---------------------------------------------------------------------------
# Input validation and cryptographic containers
# ---------------------------------------------------------------------------
def test_password_generators_reject_invalid_lengths():
    with pytest.raises(ValueError):
        v.generate_random_password(3)
    with pytest.raises(ValueError):
        v.generate_random_password(1025)
    with pytest.raises(ValueError):
        v.generate_passphrase(2)


def test_scrypt_container_round_trip_and_wrong_password():
    session = v.new_session("correct horse battery staple")
    original = {
        "GitHub": {
            "type": "password",
            "username": "user@example.com",
            "password": "secret",
        }
    }
    packed = v.pack_container(session, original)
    restored_session, restored = v.decrypt_container(packed, "correct horse battery staple")
    assert restored == original
    assert restored_session.salt == session.salt
    with pytest.raises(v.InvalidToken):
        v.decrypt_container(packed, "wrong password")


def test_container_rejects_invalid_decrypted_schema():
    session = v.new_session("test password")
    with pytest.raises(ValueError):
        v.pack_container(session, {"bad": {"type": "unknown", "password": "x"}})


def test_secure_config_write_is_atomic(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    monkeypatch.setattr(v, "CONFIG_FILE", config)
    v.save_config(theme="mono", clipboard_timeout=10)
    assert json.loads(config.read_text(encoding="utf-8")) == {
        "theme": "mono",
        "clipboard_timeout": 10,
    }
    assert not config.with_suffix(".json.tmp").exists()


def test_encrypted_export_can_be_restored():
    session = v.new_session("export password")
    original = {"Service": {"type": "password", "password": "secret", "username": "u"}}
    exported = v.EXPORT_MAGIC + v.pack_container(session, original)
    assert v.decrypt_any_backup(exported, "export password") == original


def test_corrupt_trash_is_reported(tmp_path, monkeypatch):
    trash = tmp_path / "trash.enc"
    trash.write_bytes(v.TRASH_MAGIC + b"not-valid")
    monkeypatch.setattr(v, "TRASH_FILE", trash)
    with pytest.raises(ValueError, match="trash data"):
        v.load_trash(v.new_session("password"))


def test_import_csv_and_conflict_modes(tmp_path, monkeypatch):
    csv_file = tmp_path / "browser.csv"
    csv_file.write_text(
        "name,username,password,url\n"
        "GitHub,user,secret,https://github.com\n",
        encoding="utf-8",
    )
    vault = {}
    session = v.new_session("password")
    monkeypatch.setattr(v, "save_vault", lambda _session, _vault: None)
    assert v.import_csv(vault, session, csv_file, offer_delete=False) == 1
    assert vault["GitHub"]["password"] == "secret"
    assert v.import_csv(vault, session, csv_file, on_conflict="skip", offer_delete=False) == 0
    assert v.import_csv(vault, session, csv_file, on_conflict="rename", offer_delete=False) == 1
    assert "GitHub (2)" in vault


def test_json_list_output_contains_names_only(monkeypatch, capsys):
    monkeypatch.setattr(v, "unlock_vault", lambda: (object(), {
        "GitHub": {"type": "password", "password": "must-not-print"}
    }))
    assert v.cmd_list(["--json"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output) == ["GitHub"]
    assert "must-not-print" not in output


def test_delete_command_requires_explicit_yes(monkeypatch):
    session = v.new_session("password")
    vault = {"GitHub": {"type": "password", "password": "secret"}}
    monkeypatch.setattr(v, "unlock_vault", lambda: (session, vault))
    monkeypatch.setattr(v, "save_vault", lambda _session, _vault: None)
    monkeypatch.setattr(v, "trash_add", lambda _session, name, entry: None)
    monkeypatch.setattr(v, "confirm", lambda _text: False)
    assert v.cmd_delete(["GitHub"]) == 0
    assert "GitHub" in vault


def test_delete_command_moves_entry_with_yes(monkeypatch):
    session = v.new_session("password")
    vault = {"GitHub": {"type": "password", "password": "secret"}}
    deleted = []
    monkeypatch.setattr(v, "unlock_vault", lambda: (session, vault))
    monkeypatch.setattr(v, "save_vault", lambda _session, _vault: None)
    monkeypatch.setattr(v, "trash_add", lambda _session, name, entry: deleted.append((name, entry)))
    assert v.cmd_delete(["GitHub", "--yes"]) == 0
    assert "GitHub" not in vault
    assert deleted[0][0] == "GitHub"