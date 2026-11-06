# -*- coding: utf-8 -*-
"""Vault entry models, schema validation, and version migration."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vault.constants import ENV_NAME_RE, MAX_ENTRY_HISTORY, VAULT_SCHEMA_VERSION


def hostname_of(url: str) -> str:
    """Extract a clean hostname from a URL-like string. Returns '' on failure."""
    if not url or not isinstance(url, str):
        return ""
    url = url.strip()
    if not url:
        return ""
    try:
        parsed = urlparse(url if "://" in url else "//" + url)
        host = parsed.hostname or ""
    except Exception:
        return ""
    if not host or " " in host or "." not in host:
        return ""
    return host[4:] if host.startswith("www.") else host


def parse_date(value: str) -> Optional[date]:
    """Parse an ISO format date string (YYYY-MM-DD)."""
    try:
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def days_until_expiry(expiry_date_str: str) -> Optional[int]:
    """Calculate remaining days until expiration."""
    d = parse_date(expiry_date_str)
    if d is None:
        return None
    return (d - date.today()).days


def entry_type(entry: Dict[str, Any] | str) -> str:
    """Return entry type: 'password' or 'api_key'."""
    if isinstance(entry, dict):
        return entry.get("type", "password")
    return "password"


def entry_secret(entry: Dict[str, Any] | str) -> str:
    """Extract primary secret value."""
    if not isinstance(entry, dict):
        return str(entry)
    if entry.get("type") == "api_key":
        return str(entry.get("api_key", ""))
    return str(entry.get("password", ""))


def entry_note(entry: Any) -> str:
    """Extract entry note (or username for passwords)."""
    from vault.ui import G_EMPTY

    if not isinstance(entry, dict):
        return G_EMPTY
    if entry_type(entry) == "api_key":
        return entry.get("notes") or G_EMPTY
    return entry.get("username") or G_EMPTY


def entry_totp(entry: Dict[str, Any] | str) -> str:
    """Extract TOTP secret seed."""
    if isinstance(entry, dict):
        return str(entry.get("totp_secret", "") or entry.get("totp", ""))
    return ""


def entry_tags(entry: Dict[str, Any] | str) -> List[str]:
    """Return list of entry tags."""
    if isinstance(entry, dict):
        raw = entry.get("tags", [])
        if isinstance(raw, list):
            return [str(t) for t in raw]
    return []


def entry_is_favorite(entry: Dict[str, Any] | str) -> bool:
    """Check if entry is flagged as favorite."""
    if isinstance(entry, dict):
        return bool(entry.get("favorite", False))
    return False


def entry_custom_fields(entry: Dict[str, Any] | str) -> Dict[str, str]:
    """Extract custom key-value pairs."""
    if isinstance(entry, dict):
        fields = entry.get("custom_fields", {})
        if isinstance(fields, dict):
            return {str(k): str(v) for k, v in fields.items()}
    return {}


def prune_entry_history(entry: Dict[str, Any], max_history: int = MAX_ENTRY_HISTORY) -> int:
    """Trim entry password history revisions to avoid unbounded size, returning removed count."""
    if not isinstance(entry, dict) or "history" not in entry or not isinstance(entry["history"], list):
        return 0
    hist = entry["history"]
    if len(hist) > max_history:
        removed = len(hist) - max_history
        entry["history"] = hist[-max_history:]
        return removed
    return 0


def set_expiry_relative(entry: Dict[str, Any], days: int = 90) -> str:
    """Set entry expiration date to relative offset from today in YYYY-MM-DD format."""
    target_date = date.today() + timedelta(days=days)
    val = target_date.isoformat()
    entry["expires"] = val
    return val


def validate_entry(entry: Any, name: str = "entry") -> Dict[str, Any]:
    """Validate entry schema and enforce data integrity."""
    if not isinstance(entry, dict):
        raise ValueError(f"{name} must be an object")

    entry_type_value = entry.get("type", "password")
    if entry_type_value not in ("password", "api_key"):
        raise ValueError(f"{name} has an unsupported type")

    secret_key = "api_key" if entry_type_value == "api_key" else "password"
    if not isinstance(entry.get(secret_key), str):
        raise ValueError(f"{name} is missing a valid {secret_key}")

    for key in ("username", "url", "notes", "env", "created", "expires", "totp_secret", "totp"):
        if key in entry and not isinstance(entry[key], str):
            raise ValueError(f"{name}.{key} must be a string")

    if entry.get("env") and not ENV_NAME_RE.fullmatch(entry["env"]):
        raise ValueError(f"{name}.env is not a valid environment variable name")

    for key in ("created", "expires"):
        if entry.get(key) and parse_date(entry[key]) is None:
            raise ValueError(f"{name}.{key} is not a valid YYYY-MM-DD date")

    # Optional tags validation
    if "tags" in entry and not isinstance(entry["tags"], list):
        raise ValueError(f"{name}.tags must be a list of strings")

    # Optional history validation
    if "history" in entry and not isinstance(entry["history"], list):
        raise ValueError(f"{name}.history must be a list of entries")

    # Optional custom_fields validation
    if "custom_fields" in entry and not isinstance(entry["custom_fields"], dict):
        raise ValueError(f"{name}.custom_fields must be a dictionary")

    # Optional attachments validation
    if "attachments" in entry and not isinstance(entry["attachments"], dict):
        raise ValueError(f"{name}.attachments must be a dictionary")

    return dict(entry)


def migrate_schema(data: Dict[str, Any]) -> Dict[str, Any]:
    """Evolve older vault structures to current VAULT_SCHEMA_VERSION (Improvement #20)."""
    current_version = data.get("schema_version", 1)
    entries = data.get("entries", data)

    if current_version < 2:
        # Upgrade v1 entries to support v2 properties
        for _name, entry in entries.items():
            if isinstance(entry, dict):
                if "tags" not in entry:
                    entry["tags"] = []
                if "favorite" not in entry:
                    entry["favorite"] = False
                if "history" not in entry:
                    entry["history"] = []
                if "custom_fields" not in entry:
                    entry["custom_fields"] = {}
                if "attachments" not in entry:
                    entry["attachments"] = {}
    return entries


def validate_vault_data(data: Any) -> Dict[str, Any]:
    """Validate full vault dictionary and apply necessary schema migrations."""
    if not isinstance(data, dict):
        raise ValueError("decrypted vault data must be an object")

    schema_version = data.get("schema_version", 1)
    if schema_version > VAULT_SCHEMA_VERSION:
        raise ValueError(f"unsupported vault schema version: {schema_version}")

    raw_entries = data.get("entries", data)
    if not isinstance(raw_entries, dict):
        raise ValueError("vault entries must be an object")

    # Run migration if needed
    entries = migrate_schema({"schema_version": schema_version, "entries": raw_entries})

    validated: Dict[str, Any] = {}
    for name, entry in entries.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("vault entry names must be non-empty strings")
        if isinstance(entry, dict):
            validated[name] = validate_entry(entry, f"entry '{name}'")
        else:
            # Legacy string entry fallback
            validated[name] = {
                "type": "password",
                "username": "",
                "password": str(entry),
                "tags": [],
                "favorite": False,
                "history": [],
                "custom_fields": {},
                "attachments": {},
            }
    return validated


def validate_vault_schema_detailed(data: Any) -> Tuple[bool, List[str]]:
    """Perform detailed recursive schema validation on decrypted vault structure.

    Returns a tuple of (is_valid, error_messages).
    """
    errors: List[str] = []
    if not isinstance(data, dict):
        return False, ["Decrypted vault data root must be a JSON object / dictionary."]

    schema_version = data.get("schema_version", 1)
    if not isinstance(schema_version, int) or schema_version < 1:
        errors.append("Invalid or negative schema_version.")
    elif schema_version > VAULT_SCHEMA_VERSION:
        errors.append(f"Unsupported schema_version {schema_version} (maximum supported: {VAULT_SCHEMA_VERSION}).")

    entries = data.get("entries", data)
    if not isinstance(entries, dict):
        errors.append("Vault entries container must be a dictionary.")
        return False, errors

    for name, entry in entries.items():
        if not isinstance(name, str) or not name.strip():
            errors.append(f"Invalid entry key: {name!r} (must be non-empty string).")
            continue
        if not isinstance(entry, dict):
            if not isinstance(entry, str):
                errors.append(f"Entry '{name}' must be an object or string, got {type(entry).__name__}.")
            continue

        etype = entry.get("type", "password")
        if etype not in ("password", "api_key"):
            errors.append(f"Entry '{name}' has unknown type: {etype!r}.")

        sec_key = "api_key" if etype == "api_key" else "password"
        if sec_key not in entry or not isinstance(entry[sec_key], str):
            errors.append(f"Entry '{name}' missing required secret string field '{sec_key}'.")

        for str_field in ("username", "url", "notes", "env", "created", "expires", "totp_secret", "totp"):
            if str_field in entry and not isinstance(entry[str_field], str):
                errors.append(f"Entry '{name}.{str_field}' must be a string.")

        if entry.get("env") and not ENV_NAME_RE.fullmatch(entry["env"]):
            errors.append(f"Entry '{name}.env' is not a valid environment variable name: {entry['env']!r}.")

        for date_field in ("created", "expires"):
            if entry.get(date_field) and parse_date(entry[date_field]) is None:
                errors.append(f"Entry '{name}.{date_field}' is not a valid YYYY-MM-DD date: {entry[date_field]!r}.")

        if "tags" in entry and not isinstance(entry["tags"], list):
            errors.append(f"Entry '{name}.tags' must be a list.")
        elif "tags" in entry and isinstance(entry["tags"], list):
            for t in entry["tags"]:
                if not isinstance(t, str):
                    errors.append(f"Entry '{name}.tags' contains non-string item: {t!r}.")

        if "history" in entry and not isinstance(entry["history"], list):
            errors.append(f"Entry '{name}.history' must be a list.")

        if "custom_fields" in entry and not isinstance(entry["custom_fields"], dict):
            errors.append(f"Entry '{name}.custom_fields' must be a dictionary.")

        if "attachments" in entry and not isinstance(entry["attachments"], dict):
            errors.append(f"Entry '{name}.attachments' must be a dictionary.")

    return len(errors) == 0, errors

