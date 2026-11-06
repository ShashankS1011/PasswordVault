# -*- coding: utf-8 -*-
"""Vault health diagnostics, duplicate detection, and rotation warnings."""
from __future__ import annotations

import difflib
import re
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from vault.constants import EXPIRY_WARN_DAYS, FUZZY_CUTOFF, ROTATE_AFTER_DAYS
from vault.models import days_until_expiry, entry_note, entry_secret, entry_type
from vault.ui import check_password_strength

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "welcome", "admin", "login", "iloveyou", "princess", "monkey",
    "default", "letmein", "sunshine", "master", "football", "charlie", "trustno1", "computer",
    "superman", "starwars", "pass123", "password123", "secret", "p@ssword", "root", "toor",
}


def is_common_password(password: str) -> bool:
    """Check if password appears in local top common dictionary."""
    if not password:
        return False
    return password.strip().lower() in COMMON_PASSWORDS


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
    common: List[str] = []
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
            if is_common_password(sec):
                common.append(name)

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
        "common": common,
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


def find_matches_regex(vault: Dict[str, Any], pattern_str: str) -> Tuple[List[str], Optional[str]]:
    """Search entries by regular expression pattern across name, username, URL, and notes."""
    try:
        rx = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        return [], f"Invalid regular expression: {e}"

    matches: List[str] = []
    for name, entry in vault.items():
        search_corpus = [
            name,
            entry.get("username", "") if isinstance(entry, dict) else "",
            entry.get("url", "") if isinstance(entry, dict) else "",
            entry.get("notes", "") if isinstance(entry, dict) else "",
        ]
        if any(rx.search(field) for field in search_corpus if field):
            matches.append(name)
    return sorted(matches), None


def check_entry_rotation_needed(entry: Dict[str, Any], threshold_days: int = ROTATE_AFTER_DAYS) -> Tuple[bool, int]:
    """Check whether credential age exceeds recommended rotation interval."""
    if not isinstance(entry, dict):
        return False, 0
    created_str = entry.get("created", "")
    if not created_str:
        return False, 0
    try:
        c_date = date.fromisoformat(created_str)
        age = (date.today() - c_date).days
        return age > threshold_days, age
    except ValueError:
        return False, 0



def find_similar_passwords(
    vault: Dict[str, Any],
    threshold: float = 0.75,
) -> List[Tuple[str, str, float]]:
    """Detect entries with dangerously similar password variations (shared root patterns)."""
    items = [(name, entry_secret(entry)) for name, entry in vault.items() if entry_secret(entry)]
    similar: List[Tuple[str, str, float]] = []
    seen = set()

    for i in range(len(items)):
        name1, sec1 = items[i]
        for j in range(i + 1, len(items)):
            name2, sec2 = items[j]
            if sec1 == sec2:
                continue  # Identical duplicates are handled separately
            ratio = difflib.SequenceMatcher(None, sec1, sec2).ratio()
            if ratio >= threshold:
                pair = tuple(sorted([name1, name2]))
                if pair not in seen:
                    seen.add(pair)
                    similar.append((name1, name2, round(ratio * 100, 1)))

    similar.sort(key=lambda x: -x[2])
    return similar


def calculate_entropy_audit(vault: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze and rank all vault passwords by Shannon entropy bits from weakest to strongest."""
    from vault.ui import calculate_entropy

    results: List[Dict[str, Any]] = []
    for name, entry in vault.items():
        sec = entry_secret(entry)
        if not sec:
            continue
        ent, crack_time = calculate_entropy(sec)
        results.append({
            "name": name,
            "type": entry_type(entry),
            "length": len(sec),
            "entropy": ent,
            "crack_time": crack_time,
        })
    results.sort(key=lambda x: x["entropy"])
    return results


def calculate_health_score_breakdown(report: Dict[str, Any]) -> Dict[str, Any]:
    """Provide itemized point deductions and overall grade breakdown."""
    total = report.get("total_entries", 0)
    if total == 0:
        return {"base": 100, "deductions": {}, "score": 100, "grade": "Optimal"}

    n_weak = len(report.get("weak", []))
    n_dups = sum(len(names) - 1 for names in report.get("duplicates", {}).values())
    n_expired = len(report.get("expired", []))
    n_expiring = len(report.get("expiring", []))
    n_old = len(report.get("old", []))
    n_breached = len(report.get("breached", []))

    d_weak = min(35, n_weak * 12)
    d_dups = min(30, n_dups * 10)
    d_expired = min(25, n_expired * 15)
    d_expiring = min(10, n_expiring * 5)
    d_old = min(15, n_old * 4)
    d_breached = min(40, n_breached * 25)

    deductions = {
        "weak_passwords": d_weak,
        "duplicate_passwords": d_dups,
        "expired_credentials": d_expired,
        "expiring_soon": d_expiring,
        "old_credentials": d_old,
        "breached_passwords": d_breached,
    }
    total_deduction = sum(deductions.values())
    final_score = max(0, 100 - total_deduction)

    if final_score >= 90:
        grade = "Optimal"
    elif final_score >= 75:
        grade = "Good"
    elif final_score >= 50:
        grade = "Fair"
    else:
        grade = "Poor"

    return {
        "base": 100,
        "deductions": deductions,
        "total_deduction": total_deduction,
        "score": final_score,
        "grade": grade,
    }


def collect_vault_stats(vault: Dict[str, Any]) -> Dict[str, Any]:
    """Compile comprehensive vault metrics and composition statistics."""
    from vault.models import entry_is_favorite, entry_totp

    total = len(vault)
    passwords = sum(1 for e in vault.values() if entry_type(e) == "password")
    api_keys = sum(1 for e in vault.values() if entry_type(e) == "api_key")
    totp_count = sum(1 for e in vault.values() if entry_totp(e))
    fav_count = sum(1 for e in vault.values() if entry_is_favorite(e))
    tags_pool = set()
    for e in vault.values():
        if isinstance(e, dict):
            tags_pool.update(e.get("tags", []))

    pwd_lens = [len(entry_secret(e)) for e in vault.values() if entry_secret(e) and entry_type(e) == "password"]
    avg_len = round(sum(pwd_lens) / len(pwd_lens), 1) if pwd_lens else 0.0

    return {
        "total_entries": total,
        "passwords": passwords,
        "api_keys": api_keys,
        "totp_enabled": totp_count,
        "totp_coverage_percent": round((totp_count / total * 100), 1) if total else 0.0,
        "favorites": fav_count,
        "unique_tags": len(tags_pool),
        "average_password_length": avg_len,
    }

