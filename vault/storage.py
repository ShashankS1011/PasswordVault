# -*- coding: utf-8 -*-
"""Storage management, atomic file writes, NTFS DACLs, snapshots, and file locks."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from vault.constants import (
    APP_DIR,
    ATTEMPTS_FILE,
    CONFIG_FILE,
    DEFAULT_BACKUP_RETENTION,
    NAMES_FILE,
    SNAPSHOTS_DIR,
    TRASH_DAYS,
    TRASH_FILE,
    TRASH_MAGIC,
    VAULT_FILE,
)


# ---------------------------------------------------------------------------
# Cross-Platform File Locking (Improvement #18)
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def file_lock(lock_path: Path = VAULT_FILE, timeout: float = 5.0) -> Iterator[None]:
    """Advisory multi-process lock to prevent concurrent write corruption."""
    lock_file = lock_path.with_suffix(lock_path.suffix + ".lock")
    start = time.time()
    f = open(lock_file, "a+", encoding="utf-8")
    acquired = False

    while not acquired:
        try:
            if os.name == "nt":
                import msvcrt

                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except (OSError, IOError):
            if time.time() - start >= timeout:
                f.close()
                raise TimeoutError("Vault is currently locked by another process.") from None
            time.sleep(0.1)

    try:
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        f.close()


# ---------------------------------------------------------------------------
# Secure File Writing & Permissions (Improvement #4)
# ---------------------------------------------------------------------------
def _apply_windows_acls(path: Path) -> None:
    """Restrict file permissions to current user only using icacls on Windows."""
    if os.name != "nt":
        return
    try:
        user = os.environ.get("USERNAME") or os.environ.get("USER")
        if not user:
            return
        # Remove inheritance and grant Full Control only to current user
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            creationflags=0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
    except Exception:
        pass


def secure_write(path: Path, data: bytes) -> None:
    """Atomic write with explicit flushing and restricted file permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

    if os.name == "nt":
        _apply_windows_acls(path)
    else:
        try:
            path.chmod(0o600)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Rolling Snapshots (Improvement #19)
# ---------------------------------------------------------------------------
def take_snapshot(
    file_path: Path,
    max_snapshots: int = 5,
    snapshots_dir: Optional[Path] = None,
) -> Optional[Path]:
    """Create an automatic timestamped snapshot before write operations."""
    if not file_path.exists():
        return None
    try:
        target_dir = snapshots_dir or SNAPSHOTS_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        snap_path = target_dir / f"{file_path.stem}_{timestamp}.snap"
        shutil.copy2(file_path, snap_path)

        # Retain only the most recent snapshots
        existing = sorted(target_dir.glob(f"{file_path.stem}_*.snap"), key=os.path.getmtime)
        if len(existing) > max_snapshots:
            for old in existing[:-max_snapshots]:
                try:
                    old.unlink()
                except OSError:
                    pass
        return snap_path
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tamper-Resistant Failed Attempt Tracking (Improvement #6)
# ---------------------------------------------------------------------------
def _get_machine_secret() -> bytes:
    """Derive local machine secret for HMAC signing attempt tracking."""
    guid = ""
    if os.name == "nt":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        except Exception:
            pass
    if not guid:
        guid = f"{os.environ.get('COMPUTERNAME', '')}-{os.environ.get('USERNAME', '')}-{APP_DIR}"
    return hashlib.sha256(guid.encode("utf-8")).digest()


def _read_attempts() -> Dict[str, Any]:
    try:
        if not ATTEMPTS_FILE.exists():
            return {"count": 0, "last": 0}
        content = json.loads(ATTEMPTS_FILE.read_text(encoding="utf-8"))
        count = int(content.get("count", 0))
        last = float(content.get("last", 0))
        sig = str(content.get("sig", ""))

        # Verify HMAC signature
        expected_sig = hmac.new(
            _get_machine_secret(),
            f"{count}:{last}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            # Tampering detected: penalize with maximum lockout
            return {"count": 5, "last": time.time()}
        return {"count": count, "last": last}
    except Exception:
        return {"count": 0, "last": 0}


def check_lockout() -> Tuple[bool, int]:
    """Check if login is locked out; returns (is_locked, remaining_seconds)."""
    state = _read_attempts()
    count = state.get("count", 0)
    if count >= 3:
        delay = int(min(2 ** count, 300))
        remaining = int(delay - (time.time() - state.get("last", 0)))
        if remaining > 0:
            return True, remaining
    return False, 0


def record_failure() -> int:
    """Record a failed unlock attempt and sign state."""
    state = _read_attempts()
    count = state.get("count", 0) + 1
    last = time.time()
    sig = hmac.new(
        _get_machine_secret(),
        f"{count}:{last}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    data = {"count": count, "last": last, "sig": sig}
    secure_write(ATTEMPTS_FILE, json.dumps(data).encode("utf-8"))
    return count


def clear_failures() -> None:
    """Clear failed attempts upon successful authentication."""
    try:
        ATTEMPTS_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dynamic Paths for Monkeypatching Compatibility
# ---------------------------------------------------------------------------
def _config_path() -> Path:
    import sys
    v = sys.modules.get("vault")
    return getattr(v, "CONFIG_FILE", CONFIG_FILE)


def _trash_path() -> Path:
    import sys
    v = sys.modules.get("vault")
    return getattr(v, "TRASH_FILE", TRASH_FILE)


def _vault_path() -> Path:
    import sys
    v = sys.modules.get("vault")
    return getattr(v, "VAULT_FILE", VAULT_FILE)


# ---------------------------------------------------------------------------
# Configuration Persistence
# ---------------------------------------------------------------------------
def load_config() -> Dict[str, Any]:
    path = _config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(**updates: Any) -> None:
    config = load_config()
    config.update(updates)
    secure_write(_config_path(), json.dumps(config, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# Names Index for Tab Completion
# ---------------------------------------------------------------------------
def sync_names_index(vault_data: Dict[str, Any]) -> None:
    """Sync plain list of entry names for fast tab completion if enabled."""
    cfg = load_config()
    if not cfg.get("completion_enabled", False):
        return
    try:
        lines = sorted(vault_data.keys(), key=str.lower)
        secure_write(NAMES_FILE, ("\n".join(lines) + "\n").encode("utf-8"))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Secure File Shredding (Improvement #30)
# ---------------------------------------------------------------------------
def shred_file(path: Path, passes: int = 3) -> bool:
    """Secure multi-pass file overwrite before unlinking."""
    if not path.is_file():
        return False
    try:
        size = path.stat().st_size
        with open(path, "ba+", buffering=0) as f:
            for p in range(passes):
                f.seek(0)
                if p == passes - 1:
                    f.write(b"\x00" * size)
                else:
                    f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            f.truncate(0)
        # Rename file to obscure metadata before deletion
        scrambled = path.parent / f"shred_{os.urandom(8).hex()}"
        path.rename(scrambled)
        scrambled.unlink()
        return True
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Trash Storage Management
# ---------------------------------------------------------------------------
def load_trash(session: Any) -> List[Dict[str, Any]]:
    from datetime import date, timedelta

    from cryptography.fernet import InvalidToken

    from vault.models import parse_date, validate_entry

    path = _trash_path()
    if not path.exists():
        return []
    try:
        data = path.read_bytes()
        if not data.startswith(TRASH_MAGIC):
            return []
        items = json.loads(session.fernet.decrypt(data[len(TRASH_MAGIC):]).decode())
    except (OSError, InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"trash data is damaged or cannot be decrypted: {exc}") from exc
    if not isinstance(items, list):
        raise ValueError("trash data must be a list")
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("trash contains an invalid item")
        validate_entry(item.get("entry"), f"trash entry '{item['name']}'")
    cutoff = date.today() - timedelta(days=TRASH_DAYS)
    fresh = [i for i in items if (parse_date(i.get("deleted", "")) or date.min) >= cutoff]
    return fresh


def save_trash(session: Any, items: List[Dict[str, Any]]) -> None:
    token = session.fernet.encrypt(json.dumps(items).encode())
    secure_write(_trash_path(), TRASH_MAGIC + token)


def trash_add(session: Any, name: str, entry: Any) -> None:
    items = load_trash(session)
    from datetime import date
    items.append({"name": name, "entry": entry, "deleted": date.today().isoformat()})
    save_trash(session, items)


def empty_trash(session: Any) -> None:
    save_trash(session, [])
    try:
        _trash_path().unlink(missing_ok=True)
    except Exception:
        pass


def restore_from_trash(vault: Dict[str, Any], session: Any, name: Optional[str] = None) -> bool:
    items = load_trash(session)
    if not items:
        return False
    if name:
        found = [i for i in items if i.get("name") == name]
        if not found:
            return False
        entry = found[0]["entry"]
        vault[name] = entry
        save_trash(session, [i for i in items if i.get("name") != name])
        import sys
        v = sys.modules.get("vault")
        saver = getattr(v, "save_vault", None)
        if saver:
            saver(session, vault)
        else:
            from vault.crypto import save_vault
            save_vault(session, vault)
        return True
    return False


def canonicalize_path(path: Path | str) -> Path:
    """Resolve cross-platform path safely handling tildes, env vars, and symlinks."""
    raw = os.path.expandvars(os.path.expanduser(str(path)))
    resolved = Path(raw).resolve()
    return resolved


def verify_backup(backup_path: Path, master_password: str) -> Tuple[bool, str, int]:
    """Verify an encrypted backup file without modifying the active vault state."""
    from vault.crypto import decrypt_any_backup, verify_vault_integrity
    from vault.models import validate_vault_data

    path = canonicalize_path(backup_path)
    if not path.is_file():
        return False, f"Backup file not found: {path}", 0
    try:
        data = path.read_bytes()
        valid, msg = verify_vault_integrity(data)
        if not valid:
            return False, f"Integrity check failed: {msg}", 0
        decrypted = decrypt_any_backup(data, master_password)
        validated = validate_vault_data(decrypted)
        return True, "Backup successfully verified and decrypted", len(validated)
    except Exception as exc:
        return False, f"Backup verification failed: {exc}", 0


def prune_backups(
    backup_dir: Path,
    max_backups: int = DEFAULT_BACKUP_RETENTION,
    pattern: str = "*.enc",
) -> List[Path]:
    """Prune oldest backups exceeding the retention threshold, returning removed paths."""
    dir_path = canonicalize_path(backup_dir)
    if not dir_path.is_dir():
        return []
    files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime)
    removed: List[Path] = []
    if len(files) > max_backups:
        to_delete = files[:-max_backups]
        for f in to_delete:
            try:
                f.unlink()
                removed.append(f)
            except OSError:
                pass
    return removed


def list_snapshots(snapshots_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List available rolling snapshot backups sorted chronologically."""
    target_dir = snapshots_dir or SNAPSHOTS_DIR
    if not target_dir.is_dir():
        return []
    snaps = sorted(target_dir.glob("*.snap"), key=lambda p: p.stat().st_mtime, reverse=True)
    results: List[Dict[str, Any]] = []
    for s in snaps:
        stat = s.stat()
        results.append({
            "name": s.name,
            "path": s,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    return results


def restore_snapshot(snapshot_path: Path, vault_path: Optional[Path] = None) -> Path:
    """Restore an automatic snapshot to vault file with pre-restore safety copy."""
    target_vault = vault_path or _vault_path()
    source_snap = canonicalize_path(snapshot_path)
    if not source_snap.is_file():
        raise FileNotFoundError(f"Snapshot not found: {source_snap}")

    # Take safety copy of current vault if present
    if target_vault.is_file():
        safety_path = target_vault.with_suffix(f".pre_restore_{int(time.time())}.bak")
        shutil.copy2(target_vault, safety_path)

    shutil.copy2(source_snap, target_vault)
    return target_vault

