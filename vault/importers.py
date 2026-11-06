# -*- coding: utf-8 -*-
"""Import credentials from CSV, Bitwarden JSON, and 1Password formats (Improvements #27, #30)."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from vault.models import validate_entry
from vault.storage import shred_file

CSV_ALIASES = {
    "name": ("name", "title", "login_name", "item_name", "account"),
    "url": ("url", "login_uri", "website", "web site", "origin", "webpage"),
    "username": ("username", "login_username", "user", "login", "email", "user_name"),
    "password": ("password", "login_password", "pass", "secret", "code"),
    "notes": ("notes", "note", "comment", "comments", "extra", "description"),
    "totp": ("totp", "otp", "2fa", "authenticator", "one-time password"),
    "tags": ("tags", "group", "grouping", "folder", "category"),
}


def _csv_pick(row: Dict[str, str], aliases: Tuple[str, ...]) -> str:
    lowers = {k.strip().lower(): v for k, v in row.items() if k}
    for alias in aliases:
        if alias in lowers and lowers[alias]:
            return lowers[alias].strip()
    return ""


def _pick_conflict_name(base: str, existing: Dict[str, Any]) -> str:
    if base not in existing:
        return base
    idx = 2
    while f"{base} ({idx})" in existing:
        idx += 1
    return f"{base} ({idx})"


def import_csv(
    vault: Dict[str, Any],
    session: Any,
    csv_path: Path,
    on_conflict: str = "rename",
    conflict_mode: Optional[str] = None,
    offer_delete: bool = False,
    auto_shred: bool = False,
) -> int:
    """Import credentials from standard CSV formats."""
    from vault.crypto import save_vault

    mode = conflict_mode or on_conflict
    if not csv_path.is_file():
        raise FileNotFoundError(f"File not found: {csv_path}")

    added = 0
    skipped = 0

    with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pwd = _csv_pick(row, CSV_ALIASES["password"])
            if not pwd:
                skipped += 1
                continue

            name = _csv_pick(row, CSV_ALIASES["name"])
            url = _csv_pick(row, CSV_ALIASES["url"])
            user = _csv_pick(row, CSV_ALIASES["username"])
            notes = _csv_pick(row, CSV_ALIASES["notes"])
            totp = _csv_pick(row, CSV_ALIASES["totp"])

            if not name and url:
                parsed = urlparse(url)
                name = parsed.netloc or parsed.path
            if not name:
                name = f"Imported-{added + 1}"

            if name in vault:
                if mode == "skip":
                    skipped += 1
                    continue
                elif mode == "rename":
                    name = _pick_conflict_name(name, vault)

            entry: Dict[str, Any] = {
                "type": "password",
                "username": user,
                "password": pwd,
            }
            if url:
                entry["url"] = url
            if notes:
                entry["notes"] = notes
            if totp:
                entry["totp_secret"] = totp

            vault[name] = validate_entry(entry, name)
            added += 1

    save_vault(session, vault)
    if auto_shred:
        shred_file(csv_path)

    return added


def import_bitwarden_json(
    vault: Dict[str, Any],
    session: Any,
    json_path: Path,
    conflict_mode: str = "rename",
    auto_shred: bool = False,
) -> Tuple[int, int]:
    """Import items from Bitwarden JSON export."""
    from vault.crypto import save_vault

    if not json_path.is_file():
        raise FileNotFoundError(f"File not found: {json_path}")

    data = json.loads(json_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    added = 0
    skipped = 0

    for item in items:
        login = item.get("login") or {}
        pwd = login.get("password", "")
        if not pwd and item.get("type") == 1:
            skipped += 1
            continue

        name = item.get("name") or "Unnamed"
        username = login.get("username", "")
        totp = login.get("totp", "")
        notes = item.get("notes", "")

        urls = login.get("uris", [])
        url = urls[0].get("uri", "") if urls and isinstance(urls[0], dict) else ""

        # Extract custom fields
        custom_fields: Dict[str, str] = {}
        for f in item.get("fields", []):
            if isinstance(f, dict) and f.get("name") and f.get("value"):
                custom_fields[f["name"]] = str(f["value"])

        if name in vault:
            if conflict_mode == "skip":
                skipped += 1
                continue
            elif conflict_mode == "rename":
                name = _pick_conflict_name(name, vault)

        entry = {
            "type": "password",
            "username": username,
            "password": pwd,
            "url": url,
            "notes": notes,
            "totp_secret": totp,
            "custom_fields": custom_fields,
        }
        vault[name] = validate_entry(entry, name)
        added += 1

    save_vault(session, vault)
    if auto_shred:
        shred_file(json_path)
    return added, skipped


def import_encrypted_json(
    vault: Dict[str, Any],
    session: Any,
    file_path: Path,
    passphrase: str,
    on_conflict: str = "rename",
) -> Tuple[int, int]:
    """Import credentials from an authenticated AES-256-GCM encrypted JSON envelope."""
    from vault.crypto import save_vault, unpack_encrypted_json
    from vault.models import validate_entry

    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    content = file_path.read_text(encoding="utf-8")
    payload = unpack_encrypted_json(content, passphrase)
    entries = payload.get("entries", payload)

    added = 0
    skipped = 0
    for name, entry in entries.items():
        if name in vault:
            if on_conflict == "skip":
                skipped += 1
                continue
            elif on_conflict == "rename":
                name = _pick_conflict_name(name, vault)
        vault[name] = validate_entry(entry, name)
        added += 1

    save_vault(session, vault)
    return added, skipped


def import_keepass_xml(
    vault: Dict[str, Any],
    session: Any,
    xml_path: Path,
    on_conflict: str = "rename",
    auto_shred: bool = False,
) -> Tuple[int, int]:
    """Import credentials from a KeePass 2.x XML export file."""
    import xml.etree.ElementTree as ET

    from vault.crypto import save_vault

    if not xml_path.is_file():
        raise FileNotFoundError(f"File not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        raise ValueError(f"Failed to parse KeePass XML file: {e}") from e

    added = 0
    skipped = 0

    for entry_elem in root.iter("Entry"):
        title = ""
        username = ""
        password = ""
        url = ""
        notes = ""
        custom_fields: Dict[str, str] = {}

        for str_elem in entry_elem.findall("String"):
            key_el = str_elem.find("Key")
            val_el = str_elem.find("Value")
            if key_el is not None and key_el.text:
                k = key_el.text.strip()
                v = val_el.text.strip() if val_el is not None and val_el.text else ""
                k_lower = k.lower()
                if k_lower == "title":
                    title = v
                elif k_lower in ("username", "user name"):
                    username = v
                elif k_lower == "password":
                    password = v
                elif k_lower in ("url", "website"):
                    url = v
                elif k_lower in ("notes", "comment", "comments"):
                    notes = v
                elif k_lower not in ("history",):
                    if v:
                        custom_fields[k] = v

        if not password and not title and not username:
            skipped += 1
            continue

        name = title or f"KeePass-Entry-{added + 1}"
        if name in vault:
            if on_conflict == "skip":
                skipped += 1
                continue
            elif on_conflict == "rename":
                name = _pick_conflict_name(name, vault)

        entry: Dict[str, Any] = {
            "type": "password",
            "username": username,
            "password": password,
        }
        if url:
            entry["url"] = url
        if notes:
            entry["notes"] = notes
        if custom_fields:
            entry["custom_fields"] = custom_fields

        vault[name] = validate_entry(entry, name)
        added += 1

    save_vault(session, vault)
    if auto_shred:
        shred_file(xml_path)
    return added, skipped


