# -*- coding: utf-8 -*-
"""Have I Been Pwned (HIBP) k-anonymity breach checker (Improvement #10)."""
from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple


def check_password_breach(password: str, timeout: float = 4.0) -> int:
    """Check if password appears in known data breaches using k-anonymity.

    Sends only the first 5 characters of SHA-1 hash to api.pwnedpasswords.com.
    Returns: breach count (>0), 0 if clean, or -1 on network failure.
    """
    if not password:
        return 0
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurePasswordVault-kAnonymity-Audit/3.4"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            lines = resp.read().decode("utf-8").splitlines()
            for line in lines:
                parts = line.split(":")
                if parts[0] == suffix:
                    return int(parts[1])
            return 0
    except (urllib.error.URLError, TimeoutError, OSError):
        return -1


def audit_vault_breaches(vault: Dict[str, Any]) -> List[Tuple[str, int]]:
    """Audit all unique passwords in the vault against breach databases."""
    from vault.models import entry_secret

    seen_secrets: Dict[str, int] = {}
    breached: List[Tuple[str, int]] = []

    for name, entry in vault.items():
        secret = entry_secret(entry)
        if not secret:
            continue
        if secret not in seen_secrets:
            count = check_password_breach(secret)
            seen_secrets[secret] = count
        else:
            count = seen_secrets[secret]

        if count > 0:
            breached.append((name, count))
    return breached

