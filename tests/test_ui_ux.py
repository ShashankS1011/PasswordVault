# -*- coding: utf-8 -*-
"""Comprehensive tests for the 20 terminal UI/UX improvements."""
from __future__ import annotations

from unittest.mock import MagicMock

import vault as v
from vault.clipboard import render_countdown_bar
from vault.features.generator import generate_candidates
from vault.features.health import calculate_health_score
from vault.ui import (
    THEMES,
    apply_theme,
    calculate_entropy,
    character_breakdown,
    confirm_action,
    highlight_matches,
    mask_secret,
    open_url,
    paginate_list,
    prompt_tags,
    render_credential_card,
    render_diff,
    render_health_gauge,
)


def test_calculate_entropy_and_crack_time():
    ent_zero, ct_zero = calculate_entropy("")
    assert ent_zero == 0.0
    assert ct_zero == "< 1 second"

    ent_weak, ct_weak = calculate_entropy("123456")
    assert ent_weak < 25.0
    assert ct_weak == "< 1 second"

    ent_strong, ct_strong = calculate_entropy("Correct-Horse-Battery-Staple-2026!")
    assert ent_strong > 100.0
    assert ct_strong == "centuries"


def test_character_breakdown():
    res = character_breakdown("Abc123!@#")
    assert "[len: 9]" in res
    assert "[upper: 1]" in res
    assert "[lower: 2]" in res
    assert "[digit: 3]" in res
    assert "[sym: 3]" in res


def test_mask_secret():
    assert mask_secret("") == ""
    assert mask_secret("password123", revealed=False) == "•••••••••••"
    assert mask_secret("password123", revealed=True) == "password123"
    assert mask_secret("secret", revealed=False, mask_char="*") == "******"


def test_render_health_gauge_and_score():
    empty_report = {
        "total_entries": 0,
        "weak": [],
        "duplicates": {},
        "expired": [],
        "expiring": [],
        "old": [],
    }
    assert calculate_health_score(empty_report) == 100

    flawed_report = {
        "total_entries": 10,
        "weak": [("acc1", "Weak"), ("acc2", "Weak")],
        "duplicates": {"dup_sec": ["acc3", "acc4"]},
        "expired": ["acc5"],
        "expiring": ["acc6"],
        "old": [("acc7", 400)],
        "breached": [("acc8", 5000)],
    }
    score = calculate_health_score(flawed_report)
    assert 0 <= score < 80

    gauge = render_health_gauge(score)
    assert f"{score}%" in gauge
    assert "(" in gauge and ")" in gauge

    gauge_100 = render_health_gauge(100)
    assert "100%" in gauge_100
    assert "Excellent" in gauge_100


def test_highlight_matches():
    assert highlight_matches("", "abc") == ""
    assert highlight_matches("Simple Text", "") == "Simple Text"
    res = highlight_matches("GitHub Admin", "Hub")
    assert "Hub" in res


def test_expanded_themes():
    for name in ("dracula", "nord", "solarized-dark"):
        assert name in THEMES
        assert "HEAD" in THEMES[name]
        assert "OK" in THEMES[name]
        assert "ERR" in THEMES[name]
        assert "ACCENT" in THEMES[name]
        apply_theme(name)


def test_generate_candidates():
    candidates = generate_candidates(count=3, length=22, symbols=True, exclude_ambiguous=True)
    assert len(candidates) == 3
    for cand, ent, crack_time in candidates:
        assert len(cand) == 22
        assert ent > 40.0
        assert isinstance(crack_time, str)

    passphrase_candidates = generate_candidates(count=2, words=4, sep=".")
    assert len(passphrase_candidates) == 2
    for cand, ent, _ in passphrase_candidates:
        assert len(cand.split(".")) == 4
        assert ent > 40.0


def test_render_countdown_bar():
    full_bar = render_countdown_bar(10, 10, width=10)
    assert full_bar == "[==========]"

    half_bar = render_countdown_bar(5, 10, width=10)
    assert half_bar == "[====......]" or half_bar == "[=====.....]"

    empty_bar = render_countdown_bar(0, 10, width=10)
    assert empty_bar == "[..........]"


def test_confirm_action(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert confirm_action("Proceed?", default=False) is False
    assert confirm_action("Proceed?", default=True) is True

    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert confirm_action("Proceed?", default=False) is True

    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert confirm_action("Proceed?", default=True) is False


def test_open_url_helper(monkeypatch):
    assert open_url("") is False

    mock_browser = MagicMock(return_value=True)
    monkeypatch.setattr("webbrowser.open", mock_browser)
    assert open_url("github.com") is True
    mock_browser.assert_called_with("https://github.com")

    assert open_url("https://example.com/login") is True
    mock_browser.assert_called_with("https://example.com/login")


def test_prompt_tags(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "work, dev, production")
    tags = prompt_tags(["personal", "work"])
    assert tags == ["work", "dev", "production"]

    monkeypatch.setattr("builtins.input", lambda _: "")
    default_tags = prompt_tags(["personal"], current=["existing_tag"])
    assert default_tags == ["existing_tag"]


def test_paginate_list(monkeypatch, capsys):
    assert paginate_list([]) is None

    # Small list renders directly
    items = ["item1", "item2"]
    assert paginate_list(items, page_size=10) is None
    out = capsys.readouterr().out
    assert "item1" in out
    assert "item2" in out


def test_render_diff(capsys):
    old_e = {"username": "old_user", "password": "old_password", "url": "https://old.com"}
    new_e = {"username": "new_user", "password": "new_password", "url": "https://new.com"}
    render_diff(old_e, new_e)
    out = capsys.readouterr().out
    assert "Modifications Summary" in out
    assert "username" in out
    assert "old_user" in out
    assert "new_user" in out


def test_render_credential_card(capsys):
    entry = {
        "type": "password",
        "username": "alice@example.com",
        "password": "SecretPassword99!",
        "url": "https://service.com",
        "tags": ["prod"],
        "created": "2026-01-01",
    }
    render_credential_card("MyService", entry, show_secret=False)
    out = capsys.readouterr().out
    assert "MyService" in out
    assert "alice@example.com" in out
    assert "•••••••••••••••••" in out
    assert "service.com" in out


def test_cmd_get_raw_and_quiet(monkeypatch, capsys):
    monkeypatch.setattr(v, "unlock_vault", lambda: (object(), {
        "ApiKey": {"type": "api_key", "api_key": "raw-secret-token-12345"}
    }))
    assert v.cmd_get(["ApiKey", "--raw"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "raw-secret-token-12345"


def test_cmd_list_compact(monkeypatch, capsys):
    monkeypatch.setattr(v, "unlock_vault", lambda: (object(), {
        "GitHub": {"type": "password", "username": "octocat", "tags": ["git", "dev"]},
        "AWS": {"type": "api_key", "username": "", "tags": []},
    }))
    assert v.cmd_list(["--compact"]) == 0
    out = capsys.readouterr().out
    assert "GitHub (octocat) [git, dev]" in out
    assert "AWS" in out


def test_cmd_open(monkeypatch):
    mock_open = MagicMock(return_value=True)
    monkeypatch.setattr("vault.cli.open_url", mock_open)
    monkeypatch.setattr(v, "unlock_vault", lambda: (object(), {
        "GitHub": {"type": "password", "url": "https://github.com"}
    }))
    assert v.cmd_open(["GitHub"]) == 0
    mock_open.assert_called_with("https://github.com")
