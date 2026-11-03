# -*- coding: utf-8 -*-
"""Vault health diagnostics, duplicate detection, and rotation warnings."""
from __future__ import annotations

import difflib
import re
from datetime import date
from typing import Any, Dict, List, Tuple

from vault.constants import EXPIRY_WARN_DAYS, FUZZY_CUTOFF, ROTATE_AFTER_DAYS
from vault.models import days_until_expiry, entry_note, entry_secret, entry_type
from vault.ui import check_password_strength


def find_duplicate_secret(vault: Dict[str, Any], secret: str, exclude: str = "") -> List[str]:
    """Find all entry names that share the identical secret value."""
    dups = []
    for name, entry in vault.items():
        if name == exclude:
            continue
        if entry_secret(entry) == secret:
            dups.append(name)
    return sorted(dups)


def find_all_duplicates(vault: Dict[str, Any]) -> Dict[str, List[str]]:
    """Group entries with shared passwords."""
    by_secret: Dict[str, List[str]] = {}
    for name, entry in vault.items():
        s = entry_secret(entry)
        if s:
            by_secret.setdefault(s, []).append(name)
    return {k: v for k, v in by_secret.items() if len(v) > 1}


def collect_health(vault: Dict[str, Any], check_pwned: bool = False) -> Dict[str, Any]:
    """Compile comprehensive vault health report."""
    weak: List[Tuple[str, str]] = []
    expired: List[str] = []
    expiring: List[Tuple[str, int]] = []
    old: List[Tuple[str, int]] = []
    today = date.today()

    for name, entry in vault.items():
        sec = entry_secret(entry)
        etype = entry_type(entry)

        if etype == "password":
            grade, _ = check_password_strength(sec)
            if grade == "Weak":
                weak.append((name, grade))

        exp_str = entry.get("expires", "")
        if exp_str:
            days = days_until_expiry(exp_str)
            if days is not None:
                if days < 0:
                    expired.append(name)
                elif days <= EXPIRY_WARN_DAYS:
                    expiring.append((name, days))

        created_str = entry.get("created", "")
        if created_str:
            try:
                c_date = date.fromisoformat(created_str)
                age = (today - c_date).days
                if age > ROTATE_AFTER_DAYS:
                    old.append((name, age))
            except ValueError:
                pass

    duplicates = find_all_duplicates(vault)
    report: Dict[str, Any] = {
        "total_entries": len(vault),
        "weak": weak,
        "duplicates": duplicates,
        "expired": expired,
        "expiring": expiring,
        "old": old,
    }

    if check_pwned:
        from vault.features.pwned import audit_vault_breaches

        report["breached"] = audit_vault_breaches(vault)

    return report


def calculate_health_score(report: Dict[str, Any]) -> int:
    """Calculate an overall security health score from 0 to 100%."""
    total = report.get("total_entries", 0)
    if total == 0:
        return 100

    score = 100
    n_weak = len(report.get("weak", []))
    n_dups = sum(len(names) - 1 for names in report.get("duplicates", {}).values())
    n_expired = len(report.get("expired", []))
    n_expiring = len(report.get("expiring", []))
    n_old = len(report.get("old", []))
    n_breached = len(report.get("breached", []))

    score -= min(35, n_weak * 12)
    score -= min(30, n_dups * 10)
    score -= min(25, n_expired * 15)
    score -= min(10, n_expiring * 5)
    score -= min(15, n_old * 4)
    score -= min(40, n_breached * 25)

    return max(0, min(100, score))


def find_matches(vault: Dict[str, Any], term: str, cutoff: float = FUZZY_CUTOFF) -> Tuple[List[str], str]:
    """Search entries with exact, partial, content, or typo-tolerant fuzzy matching."""
    term = term.strip().lower()
    names = list(vault)
    if not term:
        return names, "all"

    exact = [n for n in names if n.lower() == term]
    if exact:
        return exact, "exact"

    # Partial match on name
    partial = [n for n in names if term in n.lower()]
    if partial:
        return sorted(partial, key=str.lower), "partial"

    # Search inside username / notes
    content_hits = []
    for n in names:
        note_text = entry_note(vault[n]).lower()
        if term in note_text:
            content_hits.append(n)
    if content_hits:
        return sorted(content_hits, key=str.lower), "partial"

    # Fuzzy on name pieces
    scored = []
    for name in names:
        low = name.lower()
        pieces = [low] + [p for p in re.split(r"[^a-z0-9]+", low) if p]
        best = max(difflib.SequenceMatcher(None, term, p).ratio() for p in pieces)
        if best >= cutoff:
            scored.append((best, name))
    scored.sort(key=lambda s: (-s[0], s[1].lower()))
    if scored:
        return [n for _, n in scored[:8]], "similar"

    return [], "none"
