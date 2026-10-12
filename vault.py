#!/usr/bin/env python3
"""
Secure Password Vault (CLI) – v3.3.1

Usage:
  vault                         open the full menu
  vault openai                  fuzzy-find and copy secret
  vault openai --show           show the secret briefly
  vault --list                  list names only
  vault gen [--length 24]       generate password (no unlock)
  vault gen --words 6           generate passphrase
  vault edit [NAME]             edit one field
  vault restore [NAME]          restore from trash
  vault run KEY1 KEY2 -- cmd    inject secrets as env vars
  vault import file.csv         import browser CSV
  vault export [file]           encrypted export
  vault config                  change timeouts / settings
  vault doctor [--deep]         diagnostics
  vault completion ...          PowerShell tab completion
  vault --theme light           set theme
  vault --version
"""

from __future__ import annotations

import argparse
import atexit
import base64
import csv
import difflib
import getpass
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import string
import stat
import subprocess
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

# ---------------------------------------------------------------------------
# Version & Constants
# ---------------------------------------------------------------------------
CREATOR_NAME = "Shashank"
VERSION = "3.3.1"

# Default timeouts (can be changed via `vault config`)
DEFAULT_CLIPBOARD_TIMEOUT = 15
DEFAULT_SHOW_SECONDS = 10
DEFAULT_AUTO_LOCK_SECONDS = 300

MAX_LOGIN_ATTEMPTS = 3
EXPIRY_WARN_DAYS = 30
ROTATE_AFTER_DAYS = 180
TRASH_DAYS = 30
BACKUP_STALE_DAYS = 30
FUZZY_CUTOFF = 0.55

SCRYPT_N_LOG2 = 17
SCRYPT_R = 8
SCRYPT_P = 1
LEGACY_PBKDF2_ITERATIONS = 480_000

VAULT_MAGIC = b"PVLT2"
OLD_BACKUP_MAGIC = b"PVBK1"
TRASH_MAGIC = b"PVTR1"
EXPORT_MAGIC = b"PVEX1"
VAULT_SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
USER_HOME = Path.home()
APP_DIR = USER_HOME / ".local_password_vault"
APP_DIR.mkdir(parents=True, exist_ok=True)
if os.name != "nt":
    try:
        APP_DIR.chmod(0o700)
    except OSError:
        pass

VAULT_FILE = APP_DIR / "vault.enc"
SALT_FILE = APP_DIR / "salt.key"
CONFIG_FILE = APP_DIR / "config.json"
ATTEMPTS_FILE = APP_DIR / "attempts.json"
TRASH_FILE = APP_DIR / "trash.enc"
NAMES_FILE = APP_DIR / "names.txt"

# ---------------------------------------------------------------------------
# Runtime settings (loaded from config)
# ---------------------------------------------------------------------------
def _load_timeouts() -> Tuple[int, int, int]:
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        pass
    return (
        int(cfg.get("clipboard_timeout", DEFAULT_CLIPBOARD_TIMEOUT)),
        int(cfg.get("show_seconds", DEFAULT_SHOW_SECONDS)),
        int(cfg.get("auto_lock_seconds", DEFAULT_AUTO_LOCK_SECONDS)),
    )

CLIPBOARD_TIMEOUT, SHOW_SECONDS, AUTO_LOCK_SECONDS = _load_timeouts()

# ---------------------------------------------------------------------------
# Theme System
# ---------------------------------------------------------------------------
IS_TTY = sys.stdout.isatty()

THEMES: Dict[str, Dict[str, str]] = {
    "dark": {
        "HEAD": "\033[36m", "OK": "\033[32m", "ERR": "\033[31m", "WARN": "\033[33m",
        "DIM": "\033[2m", "BOLD": "\033[1m", "INV": "\033[7m", "RST": "\033[0m",
        "ACCENT": "\033[96m", "MUTED": "\033[90m", "BOX": "\033[36m",
    },
    "light": {
        "HEAD": "\033[34m", "OK": "\033[38;5;28m", "ERR": "\033[31m", "WARN": "\033[38;5;130m",
        "DIM": "\033[38;5;243m", "BOLD": "\033[1m", "INV": "\033[7m", "RST": "\033[0m",
        "ACCENT": "\033[38;5;25m", "MUTED": "\033[38;5;245m", "BOX": "\033[34m",
    },
    "contrast": {
        "HEAD": "\033[1;96m", "OK": "\033[1;92m", "ERR": "\033[1;91m", "WARN": "\033[1;93m",
        "DIM": "", "BOLD": "\033[1m", "INV": "\033[7m", "RST": "\033[0m",
        "ACCENT": "\033[1;96m", "MUTED": "\033[1;37m", "BOX": "\033[1;96m",
    },
    "mono": {k: "" for k in ("HEAD", "OK", "ERR", "WARN", "DIM", "BOLD", "INV", "RST", "ACCENT", "MUTED", "BOX")},
}
THEME_NAMES = list(THEMES)

HEAD = OK = ERR = WARN = DIM = BOLD = INV = RST = ACCENT = MUTED = BOX = ""
_vt_enabled = False


def apply_theme(name: str) -> None:
    global _vt_enabled
    globals().update(THEMES.get(name, THEMES["dark"]))
    if name != "mono" and os.name == "nt" and not _vt_enabled:
        os.system("")
        _vt_enabled = True


def _can_print(chars: str) -> bool:
    try:
        chars.encode(getattr(sys.stdout, "encoding", None) or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


if _can_print("═█░›✓✗…·—│┌┐└┘─⠋"):
    G_RULE, G_BAR_ON, G_BAR_OFF, G_PROMPT = "═", "█", "░", "›"
    G_OK, G_ERR, G_ELLIPSIS, G_DOT, G_EMPTY = "✓", "✗", "…", "·", "—"
    G_TL, G_TR, G_BL, G_BR, G_H, G_V = "┌", "┐", "└", "┘", "─", "│"
    SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
else:
    G_RULE, G_BAR_ON, G_BAR_OFF, G_PROMPT = "=", "#", "-", ">"
    G_OK, G_ERR, G_ELLIPSIS, G_DOT, G_EMPTY = "+", "x", "~", "|", "-"
    G_TL, G_TR, G_BL, G_BR, G_H, G_V = "+", "+", "+", "+", "-", "|"
    SPINNER = ["|", "/", "-", "\\"]
G_WARN = "!"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def term_width() -> int:
    return max(62, min(shutil.get_terminal_size((80, 24)).columns, 92))


def fit(text: str, width: int) -> str:
    if len(text) > width:
        return text[: max(0, width - 1)] + G_ELLIPSIS
    return text.ljust(width)


def clear_screen() -> None:
    if IS_TTY:
        os.system("cls" if os.name == "nt" else "clear")


def wipe_screen() -> None:
    if IS_TTY:
        clear_screen()
        print("\033[3J\033[2J\033[H", end="", flush=True)


def _emit(color: str, glyph: str, msg: str) -> None:
    lines = str(msg).split("\n")
    print(f"  {color}{glyph}  {lines[0]}{RST}")
    for extra in lines[1:]:
        print(f"  {color}   {extra}{RST}")


def ok(msg: str) -> None:
    _emit(OK, G_OK, msg)


def err(msg: str) -> None:
    _emit(ERR, G_ERR, msg)


def warn(msg: str) -> None:
    _emit(WARN, G_WARN, msg)


def note(msg: str = "") -> None:
    for line in str(msg).split("\n"):
        print(f"  {DIM}{line}{RST}")


def prompt(text: str) -> str:
    return input(f"  {ACCENT}{G_PROMPT}{RST} {text}")


def secret_prompt(text: str) -> str:
    return getpass.getpass(f"  {ACCENT}{G_PROMPT}{RST} {text}")


def pause(text: str = "Press Enter to return") -> None:
    input(f"\n  {MUTED}{text}{G_ELLIPSIS}{RST} ")


def confirm(text: str) -> bool:
    return input(f"  {WARN}{text} [Y/N]:{RST} ").strip().lower() == "y"


def box_top(width: int) -> str:
    return f"{BOX}{G_TL}{G_H * (width - 2)}{G_TR}{RST}"


def box_bottom(width: int) -> str:
    return f"{BOX}{G_BL}{G_H * (width - 2)}{G_BR}{RST}"


def box_line(text: str, width: int) -> str:
    plain = _ANSI_RE.sub("", text)
    pad = width - 2 - len(plain)
    if pad < 0:
        text = text[: width - 5] + G_ELLIPSIS
        pad = 0
    return f"{BOX}{G_V}{RST} {text}{' ' * pad}{BOX}{G_V}{RST}"


def print_banner() -> None:
    width = min(term_width(), 58)
    print()
    print(f"  {box_top(width)}")
    print(f"  {box_line(f'{BOLD}SECURE PASSWORD VAULT{RST}  {MUTED}v{VERSION}{RST}', width)}")
    print(f"  {box_line(f'{DIM}Developed by {CREATOR_NAME}{RST}', width)}")
    print(f"  {box_bottom(width)}")
    print()


def print_header(title: str) -> None:
    clear_screen()
    width = min(term_width(), 58)
    print()
    print(f"  {box_top(width)}")
    print(f"  {box_line(f'{BOLD}{HEAD}{title}{RST}', width)}")
    print(f"  {box_bottom(width)}")
    print()


# ---------------------------------------------------------------------------
# Animated spinner (real animation during blocking work)
# ---------------------------------------------------------------------------
class Spinner:
    def __init__(self, msg: str = "Working") -> None:
        self.msg = msg
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> "Spinner":
        if IS_TTY:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        if IS_TTY:
            print(" " * 60, end="\r", flush=True)

    def _run(self) -> None:
        idx = 0
        while not self._stop.is_set():
            frame = SPINNER[idx % len(SPINNER)]
            print(f"  {DIM}{frame}  {self.msg}{G_ELLIPSIS}{RST}", end="\r", flush=True)
            idx += 1
            time.sleep(0.08)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------
def load_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(**updates: Any) -> None:
    config = load_config()
    config.update(updates)
    secure_write(CONFIG_FILE, json.dumps(config, indent=2).encode("utf-8"))


def effective_theme(no_color: bool = False, requested: Optional[str] = None) -> str:
    if no_color or os.environ.get("NO_COLOR") or not IS_TTY:
        return "mono"
    chosen = requested or load_config().get("theme", "dark")
    return chosen if chosen in THEMES else "dark"


apply_theme(effective_theme())


# ---------------------------------------------------------------------------
# Secure write
# ---------------------------------------------------------------------------
def secure_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def validate_entry(entry: Any, name: str = "entry") -> Dict[str, Any]:
    if not isinstance(entry, dict):
        raise ValueError(f"{name} must be an object")
    entry_type_value = entry.get("type", "password")
    if entry_type_value not in ("password", "api_key"):
        raise ValueError(f"{name} has an unsupported type")
    secret_key = "api_key" if entry_type_value == "api_key" else "password"
    if not isinstance(entry.get(secret_key), str):
        raise ValueError(f"{name} is missing a valid {secret_key}")
    for key in ("username", "url", "notes", "env", "created", "expires"):
        if key in entry and not isinstance(entry[key], str):
            raise ValueError(f"{name}.{key} must be a string")
    if entry.get("env") and not ENV_NAME_RE.fullmatch(entry["env"]):
        raise ValueError(f"{name}.env is not a valid environment variable name")
    for key in ("created", "expires"):
        if entry.get(key) and parse_date(entry[key]) is None:
            raise ValueError(f"{name}.{key} is not a valid YYYY-MM-DD date")
    return dict(entry)


def validate_vault_data(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("decrypted vault data must be an object")
    schema_version = data.get("schema_version", VAULT_SCHEMA_VERSION)
    if schema_version != VAULT_SCHEMA_VERSION:
        raise ValueError(f"unsupported vault schema version: {schema_version}")
    entries = data.get("entries", data)
    if not isinstance(entries, dict):
        raise ValueError("vault entries must be an object")
    validated: Dict[str, Any] = {}
    for name, entry in entries.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("vault entry names must be non-empty strings")
        # Legacy containers store entries directly at the top level.
        validated[name] = validate_entry(entry, f"entry '{name}'") if isinstance(entry, dict) else {
            "type": "password",
            "username": "",
            "password": str(entry),
        }
    return validated


# ---------------------------------------------------------------------------
# Clipboard (with Windows clip.exe fallback)
# ---------------------------------------------------------------------------
_last_copied: Optional[str] = None


def _clipboard_copy(text: str) -> bool:
    """Try pyperclip first, then Windows clip.exe."""
    if HAS_PYPERCLIP:
        try:
            pyperclip.copy(text)
            return True
        except Exception:
            pass

    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["clip"],
                input=text.encode("utf-16le"),
                check=True,
                capture_output=True,
            )
            return proc.returncode == 0
        except Exception:
            pass
    return False


def _clipboard_paste() -> str:
    if HAS_PYPERCLIP:
        try:
            return pyperclip.paste()
        except Exception:
            pass
    return ""


def clear_clipboard_if_ours() -> None:
    global _last_copied
    try:
        if _last_copied and _clipboard_paste() == _last_copied:
            _clipboard_copy("")
            _last_copied = None
    except Exception:
        pass


atexit.register(clear_clipboard_if_ours)


def clipboard_cleaner_main() -> None:
    digest = sys.stdin.readline().strip()
    delay = float(sys.stdin.readline().strip())
    time.sleep(delay)
    try:
        current = _clipboard_paste()
        if hashlib.sha256(current.encode()).hexdigest() == digest:
            _clipboard_copy("")
    except Exception:
        pass


def spawn_clipboard_cleaner(text: str, timeout: int) -> bool:
    try:
        frozen = getattr(sys, "frozen", False)
        cmd = [sys.executable, "--clear-clipboard"]
        if not frozen:
            cmd = [sys.executable, str(Path(__file__).resolve()), "--clear-clipboard"]
        env = dict(os.environ)
        if frozen:
            env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        kwargs: Dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "env": env,
        }
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
        digest = hashlib.sha256(text.encode()).hexdigest()
        proc.stdin.write(f"{digest}\n{timeout}\n".encode())
        proc.stdin.close()
        return True
    except Exception:
        return False


def copy_with_autoclear(text: str, timeout: int = CLIPBOARD_TIMEOUT, block_if_needed: bool = False) -> None:
    global _last_copied
    if not _clipboard_copy(text):
        err("Clipboard is not available.")
        note("Install pyperclip (`pip install pyperclip`) or use --show.")
        print(f"\n  Secret (copy manually):\n  {INV} {text} {RST}\n")
        return

    helper_started = spawn_clipboard_cleaner(text, timeout)
    _last_copied = None if helper_started else text
    print()
    ok(f"Copied to clipboard  ·  auto-clears in {timeout}s")
    if helper_started:
        return

    if block_if_needed:
        try:
            for remaining in range(timeout, 0, -1):
                if IS_TTY:
                    print(f"\r  {WARN}Clipboard clears in {remaining:2d}s{RST}  {MUTED}(Ctrl+C to clear now){RST}  ",
                          end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        clear_clipboard_if_ours()
        if IS_TTY:
            print("\r" + " " * 70, end="\r")
        ok("Clipboard cleared.")
    else:
        def clear() -> None:
            time.sleep(timeout)
            clear_clipboard_if_ours()
        threading.Thread(target=clear, daemon=True).start()


def show_secret_briefly(label: str, secret: str, seconds: int = SHOW_SECONDS) -> None:
    print(f"\n  {MUTED}{label}{RST}")
    print(f"  {INV} {secret} {RST}\n")
    try:
        for remaining in range(seconds, 0, -1):
            if IS_TTY:
                print(f"\r  {WARN}Hiding in {remaining:2d}s{RST}  {MUTED}(Ctrl+C to hide now){RST}  ",
                      end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    wipe_screen()
    ok("Secret hidden.")


def get_or_set_username() -> str:
    name = load_config().get("name")
    if name:
        return str(name)
    clear_screen()
    print_banner()
    name = prompt("Welcome! What should I call you? ").strip() or "Friend"
    save_config(name=name)
    return name


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------
def password_score(password: str) -> int:
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    return score


def check_password_strength(password: str) -> Tuple[str, str]:
    score = password_score(password)
    if score < 3:
        return "Weak", ERR
    if score < 5:
        return "Moderate", WARN
    return "Strong", OK


def strength_line(password: str) -> str:
    grade, color = check_password_strength(password)
    filled = round(password_score(password) / 6 * 10)
    bar = G_BAR_ON * filled + G_BAR_OFF * (10 - filled)
    return f"{color}{grade} {bar}{RST}"


def generate_random_password(length: int = 20, symbols: bool = True) -> str:
    minimum = 4 if symbols else 3
    if not isinstance(length, int) or length < minimum:
        raise ValueError(f"password length must be at least {minimum}")
    if length > 1024:
        raise ValueError("password length must not exceed 1024")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(string.punctuation)
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------
class Session:
    def __init__(self, key: bytes, salt: bytes, n_log2: int = SCRYPT_N_LOG2, r: int = SCRYPT_R, p: int = SCRYPT_P) -> None:
        self.key = key
        self.salt = salt
        self.n_log2 = n_log2
        self.r = r
        self.p = p
        self.fernet = Fernet(key)


def derive_scrypt_key(master_password: str, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def derive_legacy_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def new_session(master_password: str) -> Session:
    salt = os.urandom(16)
    with Spinner("Deriving key"):
        key = derive_scrypt_key(master_password, salt, SCRYPT_N_LOG2, SCRYPT_R, SCRYPT_P)
    return Session(key, salt)


def verify_master_password(session: Session, master_password: str) -> bool:
    with Spinner("Checking"):
        key = derive_scrypt_key(master_password, session.salt, session.n_log2, session.r, session.p)
    return secrets.compare_digest(key, session.key)


_HEADER_LEN = len(VAULT_MAGIC) + 16 + 3


def pack_container(session: Session, vault_data: Dict[str, Any]) -> bytes:
    validate_vault_data(vault_data)
    payload = {"schema_version": VAULT_SCHEMA_VERSION, "entries": vault_data}
    token = session.fernet.encrypt(json.dumps(payload).encode())
    header = VAULT_MAGIC + session.salt + bytes([session.n_log2, session.r, session.p])
    return header + token


def decrypt_container(data: bytes, master_password: str) -> Tuple[Session, Dict[str, Any]]:
    if len(data) <= _HEADER_LEN:
        raise ValueError("vault file too short")
    salt = data[len(VAULT_MAGIC):len(VAULT_MAGIC) + 16]
    n_log2, r, p = data[len(VAULT_MAGIC) + 16:_HEADER_LEN]
    if not (10 <= n_log2 <= 20 and 1 <= r <= 16 and 1 <= p <= 4):
        raise ValueError("unsupported encryption settings")
    with Spinner("Unlocking"):
        key = derive_scrypt_key(master_password, salt, n_log2, r, p)
        payload = json.loads(Fernet(key).decrypt(data[_HEADER_LEN:]).decode())
        vault = validate_vault_data(payload)
    return Session(key, salt, n_log2, r, p), vault


def decrypt_legacy(token: bytes, master_password: str, salt: bytes) -> Dict[str, Any]:
    key = derive_legacy_key(master_password, salt)
    return validate_vault_data(json.loads(Fernet(key).decrypt(token).decode()))


def decrypt_any_backup(data: bytes, master_password: str) -> Dict[str, Any]:
    if data.startswith(VAULT_MAGIC):
        return decrypt_container(data, master_password)[1]
    if data.startswith(EXPORT_MAGIC):
        return decrypt_container(data[len(EXPORT_MAGIC):], master_password)[1]
    if data.startswith(OLD_BACKUP_MAGIC):
        start = len(OLD_BACKUP_MAGIC)
        return decrypt_legacy(data[start + 16:], master_password, data[start:start + 16])
    for path in (SALT_FILE, SALT_FILE.with_suffix(".v1.bak")):
        if path.exists():
            salt = path.read_bytes()
            try:
                return decrypt_legacy(data, master_password, salt)
            except InvalidToken:
                continue
    raise InvalidToken()


def save_vault(session: Session, vault_data: Dict[str, Any]) -> None:
    secure_write(VAULT_FILE, pack_container(session, vault_data))
    sync_names_index(vault_data)


def open_vault_file(master_password: str) -> Tuple[Optional[Session], Dict[str, Any], bool]:
    data = VAULT_FILE.read_bytes()
    if data.startswith(VAULT_MAGIC):
        session, vault = decrypt_container(data, master_password)
        return session, vault, False
    salt = SALT_FILE.read_bytes()
    return None, decrypt_legacy(data, master_password, salt), True


def migrate_to_scrypt(master_password: str, vault: Dict[str, Any]) -> Session:
    shutil.copy2(VAULT_FILE, VAULT_FILE.with_suffix(".enc.v1.bak"))
    session = new_session(master_password)
    save_vault(session, vault)
    with open(VAULT_FILE, "rb") as f:
        _, check = decrypt_container(f.read(), master_password)
    if check != vault:
        shutil.copy2(VAULT_FILE.with_suffix(".enc.v1.bak"), VAULT_FILE)
        raise RuntimeError("upgrade verification failed; original vault left untouched")
    if SALT_FILE.exists():
        SALT_FILE.rename(SALT_FILE.with_suffix(".v1.bak"))
    return session


# ---------------------------------------------------------------------------
# Failed-login delay
# ---------------------------------------------------------------------------
def _read_attempts() -> Dict[str, Any]:
    try:
        with open(ATTEMPTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"count": 0, "last": 0}


def check_lockout() -> bool:
    state = _read_attempts()
    count = state.get("count", 0)
    if count >= 3:
        remaining = int(min(2 ** count, 300) - (time.time() - state.get("last", 0)))
        if remaining > 0:
            err(f"Too many failed attempts. Try again in {remaining}s.")
            return False
    return True


def record_failure() -> None:
    state = _read_attempts()
    secure_write(
        ATTEMPTS_FILE,
        json.dumps({"count": state.get("count", 0) + 1, "last": time.time()}).encode(),
    )


def clear_failures() -> None:
    try:
        ATTEMPTS_FILE.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Entry helpers
# ---------------------------------------------------------------------------
def entry_type(entry: Any) -> str:
    return entry.get("type", "password") if isinstance(entry, dict) else "password"


def entry_secret(entry: Any) -> str:
    if isinstance(entry, dict):
        return entry.get("api_key") if entry_type(entry) == "api_key" else entry.get("password", "")
    return str(entry)


def entry_note(entry: Any) -> str:
    if not isinstance(entry, dict):
        return G_EMPTY
    if entry_type(entry) == "api_key":
        return entry.get("notes") or G_EMPTY
    return entry.get("username") or G_EMPTY


def parse_date(value: str) -> Optional[date]:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def days_until_expiry(entry: Any) -> Optional[int]:
    expires = parse_date(entry.get("expires", "")) if isinstance(entry, dict) else None
    return (expires - date.today()).days if expires else None


def expiry_cell(entry: Any) -> Tuple[str, str]:
    days = days_until_expiry(entry)
    if days is None:
        return G_EMPTY, DIM
    if days < 0:
        return f"expired {-days}d ago", ERR
    if days == 0:
        return "today", WARN
    if days <= EXPIRY_WARN_DAYS:
        return f"in {days} day{'s' if days != 1 else ''}", WARN
    return entry.get("expires", G_EMPTY), DIM


def ask_optional_date(text: str) -> str:
    while True:
        value = prompt(text).strip()
        if not value:
            return ""
        try:
            return date.fromisoformat(value).isoformat()
        except ValueError:
            err("Please use the format YYYY-MM-DD (e.g. 2027-03-31).")


# ---------------------------------------------------------------------------
# Improved hostname_of (fixed)
# ---------------------------------------------------------------------------
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

    if not host:
        return ""

    # Reject hostnames that contain spaces or are clearly not domains
    if " " in host or "." not in host:
        return ""

    return host[4:] if host.startswith("www.") else host


# ---------------------------------------------------------------------------
# Fuzzy matching (now also searches username + notes)
# ---------------------------------------------------------------------------
def find_matches(vault: Dict[str, Any], term: str) -> Tuple[List[str], str]:
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

    # Also search inside username / notes
    content_hits = []
    for n in names:
        note = entry_note(vault[n]).lower()
        if term in note:
            content_hits.append(n)
    if content_hits:
        return sorted(content_hits, key=str.lower), "partial"

    # Fuzzy on name
    scored = []
    for name in names:
        low = name.lower()
        pieces = [low] + [p for p in re.split(r"[^a-z0-9]+", low) if p]
        best = max(difflib.SequenceMatcher(None, term, p).ratio() for p in pieces)
        if best >= FUZZY_CUTOFF:
            scored.append((best, name))
    scored.sort(key=lambda s: (-s[0], s[1].lower()))
    if scored:
        return [n for _, n in scored[:8]], "similar"
    return [], "none"


def resolve_name(vault: Dict[str, Any], term: str, action: str = "Use") -> Optional[str]:
    matches, kind = find_matches(vault, term)
    if not matches:
        err(f"Nothing in the vault matches '{term}'. Try: vault --list")
        return None
    if kind == "similar":
        note(f"No exact match for '{term}'. Did you mean:")
        if len(matches) == 1:
            print_table(vault, matches)
            print()
            return matches[0] if confirm(f"{action} '{matches[0]}'?") else None
        return choose_match(vault, matches)
    if len(matches) == 1:
        return matches[0]
    return choose_match(vault, matches)


# ---------------------------------------------------------------------------
# Table & selection
# ---------------------------------------------------------------------------
def print_table(vault: Dict[str, Any], names: List[str], numbered: bool = False) -> None:
    exp_w = 15
    fixed = 2 + (4 if numbered else 0) + 4 + 2 + 2 + 2 + exp_w
    available = max(24, term_width() - fixed)
    name_w = min(max([len(n) for n in names] + [4]), 26)
    note_w = min(max([len(entry_note(vault[n])) for n in names] + [5]), 24)
    if name_w + note_w > available:
        name_w = max(10, int(available * 0.55))
        note_w = max(8, available - name_w)

    lead = "  " + (" #  " if numbered else "")
    print(f"{MUTED}{lead}TYPE  {fit('NAME', name_w)}  {fit('NOTES', note_w)}  EXPIRES{RST}")
    print(f"  {MUTED}{G_H * (term_width() - 4)}{RST}")
    for idx, name in enumerate(names, start=1):
        entry = vault[name]
        is_api = entry_type(entry) == "api_key"
        num = f"{MUTED}{idx:>2}{RST}  " if numbered else ""
        type_cell = f"{HEAD}API {RST}" if is_api else f"{DIM}PWD {RST}"
        exp_text, exp_color = expiry_cell(entry)
        print(
            f"  {num}{type_cell}  {BOLD}{fit(name, name_w)}{RST}  "
            f"{DIM}{fit(entry_note(entry), note_w)}{RST}  {exp_color}{fit(exp_text, exp_w)}{RST}".rstrip()
        )


def choose_match(vault: Dict[str, Any], matches: List[str]) -> Optional[str]:
    print_table(vault, matches, numbered=True)
    print()
    selection = prompt(f"Enter number {MUTED}(or press Enter to cancel){RST}: ").strip()
    if selection.isdigit() and 0 <= int(selection) - 1 < len(matches):
        return matches[int(selection) - 1]
    if selection:
        err("Invalid number selection.")
    return None


def pick_entry(vault: Dict[str, Any], title: str, allow_search: bool = True) -> Optional[str]:
    print_header(title)
    if not vault:
        note("Vault is empty.")
        pause()
        return None

    search_term = ""
    if allow_search:
        search_term = prompt(f"Search by name / note {MUTED}(or press Enter to see all){RST}: ").strip().lower()
        print()

    matches, kind = find_matches(vault, search_term)
    if not matches:
        err(f"Nothing found matching '{search_term}'.")
        pause()
        return None
    if kind == "similar":
        note(f"No exact match for '{search_term}'. Similar names:")
    return choose_match(vault, matches)


def deliver_secret(name: str, entry: Any, show: bool = False, quick: bool = False) -> None:
    if entry_type(entry) == "api_key":
        days = days_until_expiry(entry)
        if days is not None and days < 0:
            warn(f"This API key expired {-days} day(s) ago.")
    if show:
        show_secret_briefly(name, entry_secret(entry))
    else:
        copy_with_autoclear(entry_secret(entry), block_if_needed=quick)


# ---------------------------------------------------------------------------
# Duplicate secret detection
# ---------------------------------------------------------------------------
def find_duplicate_secret(vault: Dict[str, Any], secret: str, exclude: Optional[str] = None) -> List[str]:
    hits = []
    for name, entry in vault.items():
        if name == exclude:
            continue
        if entry_secret(entry) == secret:
            hits.append(name)
    return hits


# ---------------------------------------------------------------------------
# Trash
# ---------------------------------------------------------------------------
def load_trash(session: Session) -> List[Dict[str, Any]]:
    if not TRASH_FILE.exists():
        return []
    try:
        data = TRASH_FILE.read_bytes()
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
    fresh = [i for i in items if (parse_date(i.get("deleted", "")) or date.today()) >= cutoff]
    if len(fresh) != len(items):
        save_trash(session, fresh)
    return fresh


def save_trash(session: Session, items: List[Dict[str, Any]]) -> None:
    if not items:
        try:
            TRASH_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        return
    token = session.fernet.encrypt(json.dumps(items).encode())
    secure_write(TRASH_FILE, TRASH_MAGIC + token)


def trash_add(session: Session, name: str, entry: Any) -> None:
    items = load_trash(session)
    items.append({"name": name, "entry": entry, "deleted": date.today().isoformat()})
    save_trash(session, items)


def print_trash_table(items: List[Dict[str, Any]]) -> None:
    name_w = min(max([len(i["name"]) for i in items] + [4]), 30)
    print(f"{MUTED}  {'#':>2}  TYPE  {fit('NAME', name_w)}  DELETED{RST}")
    print(f"  {MUTED}{G_H * (term_width() - 4)}{RST}")
    for idx, item in enumerate(items, start=1):
        is_api = entry_type(item["entry"]) == "api_key"
        type_cell = f"{HEAD}API {RST}" if is_api else f"{DIM}PWD {RST}"
        deleted = parse_date(item.get("deleted", ""))
        ago = (date.today() - deleted).days if deleted else 0
        when = "today" if ago == 0 else f"{ago} day{'s' if ago != 1 else ''} ago"
        print(f"  {MUTED}{idx:>2}{RST}  {type_cell}  {BOLD}{fit(item['name'], name_w)}{RST}  {DIM}{when}{RST}")


def restore_from_trash(vault: Dict[str, Any], session: Session, term: str = "") -> bool:
    items = load_trash(session)
    if not items:
        note("The trash is empty.")
        return False
    shown = items
    if term:
        names = {i: it["name"] for i, it in enumerate(items)}
        matches, _ = find_matches({v: None for v in names.values()}, term)
        shown = [it for it in items if it["name"] in matches]
        if not shown:
            err(f"Nothing in the trash matches '{term}'.")
            return False

    note(f"Deleted entries are kept for {TRASH_DAYS} days.\n")
    print_trash_table(shown)
    print()
    selection = prompt(f"Enter number to restore {MUTED}(or press Enter to cancel){RST}: ").strip()
    if not (selection.isdigit() and 1 <= int(selection) <= len(shown)):
        if selection:
            err("Invalid number selection.")
        return False

    item = shown[int(selection) - 1]
    name = item["name"]
    if name in vault:
        choice = prompt(f"'{name}' already exists. (R)ename the restored one, (O)verwrite, (C)ancel [R/O/C]: ").strip().lower()
        if choice == "o":
            pass
        elif choice == "r":
            i = 2
            while f"{name} ({i})" in vault:
                i += 1
            name = f"{name} ({i})"
        else:
            warn("Restore cancelled.")
            return False

    vault[name] = item["entry"]
    save_vault(session, vault)
    items.remove(item)
    save_trash(session, items)
    ok(f"Restored '{name}'.")
    return True


def empty_trash(session: Session) -> None:
    items = load_trash(session)
    if not items:
        note("The trash is already empty.")
        return
    if confirm(f"Permanently delete {len(items)} item(s) from the trash? This can't be undone."):
        save_trash(session, [])
        ok("Trash emptied.")
    else:
        warn("Cancelled.")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def ask_new_master_password() -> str:
    while True:
        pw1 = secret_prompt("New Master Password: ")
        if len(pw1) < 8:
            err("Use at least 8 characters (12+ is much better).")
            continue
        print(f"  Strength: {strength_line(pw1)}")
        if check_password_strength(pw1)[0] == "Weak" and not confirm("That's weak. Use it anyway?"):
            continue
        if secret_prompt("Confirm Master Password: ") != pw1:
            err("Passwords do not match. Try again.")
            continue
        return pw1


def unlock_vault() -> Tuple[Optional[Session], Optional[Dict[str, Any]]]:
    if not VAULT_FILE.exists():
        warn("No vault found yet — let's create one.")
        warn("If you forget the master password, nothing can recover your data.\n")
        master_pass = ask_new_master_password()
        session = new_session(master_pass)
        save_vault(session, {})
        return session, {}

    if not check_lockout():
        return None, None

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        master_pass = secret_prompt("Enter your Master Password to unlock the vault: ")
        try:
            session, vault, was_legacy = open_vault_file(master_pass)
        except InvalidToken:
            record_failure()
            err("Incorrect Master Password!")
            if attempt < MAX_LOGIN_ATTEMPTS:
                time.sleep(attempt)
            continue
        except FileNotFoundError:
            err(f"salt.key is missing from {APP_DIR}, so this old-format vault\n"
                "can't be unlocked. Restore salt.key from your backup/old copy.")
            return None, None
        except (ValueError, UnicodeDecodeError):
            err("Vault file is damaged and could not be read.")
            return None, None

        clear_failures()
        if was_legacy:
            note("Upgrading your vault to stronger encryption (one time)...")
            try:
                session = migrate_to_scrypt(master_pass, vault)
            except Exception as e:
                err(f"Upgrade failed: {e}")
                return None, None
            ok("Vault upgraded to scrypt.")
            warn(f"Safety copies kept as vault.enc.v1.bak and salt.key.v1.bak in {APP_DIR}.\n"
                 f"Once everything works, DELETE them.")
        return session, vault

    err("Too many incorrect attempts.")
    return None, None


def reauthenticate(session: Session) -> bool:
    if not check_lockout():
        return False
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = secret_prompt("Master Password required: ")
        if verify_master_password(session, password):
            clear_failures()
            return True
        record_failure()
        err("Incorrect Master Password.")
        if attempt < MAX_LOGIN_ATTEMPTS:
            time.sleep(attempt)
    return False


class AutoLock:
    def __init__(self, timeout: int = AUTO_LOCK_SECONDS) -> None:
        self.timeout = timeout
        self.locked = False
        self._armed_at: Optional[float] = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def arm(self) -> None:
        self._armed_at = time.time()

    def disarm(self) -> None:
        self._armed_at = None

    def stop(self) -> None:
        self._stop.set()

    def _watch(self) -> None:
        while not self._stop.wait(1.0):
            armed_at = self._armed_at
            if armed_at and not self.locked and time.time() - armed_at > self.timeout:
                self.locked = True
                wipe_screen()
                print()
                warn(f"Vault locked after {int(self.timeout // 60) or 1} min of inactivity.\n"
                     f"Press Enter, then enter your master password to continue.")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
def collect_health(vault: Dict[str, Any]) -> Dict[str, Any]:
    weak: List[str] = []
    expired: List[str] = []
    expiring: List[str] = []
    old_keys: List[str] = []
    secret_groups: Dict[str, List[str]] = {}
    n_pwd = sum(1 for e in vault.values() if entry_type(e) == "password")

    for site, entry in vault.items():
        secret = entry_secret(entry)
        secret_groups.setdefault(secret, []).append(site)

        if entry_type(entry) == "password":
            if check_password_strength(secret)[0] == "Weak":
                weak.append(site)
        else:
            days = days_until_expiry(entry)
            if days is not None and days < 0:
                expired.append(site)
            elif days is not None and days <= EXPIRY_WARN_DAYS:
                expiring.append(f"{site} ({days}d left)")
            created = parse_date(entry.get("created", ""))
            if created and (date.today() - created).days > ROTATE_AFTER_DAYS:
                old_keys.append(f"{site} (saved {created.isoformat()})")

    return {
        "n_pwd": n_pwd,
        "n_api": len(vault) - n_pwd,
        "weak": weak,
        "duplicates": {s: sites for s, sites in secret_groups.items() if len(sites) > 1},
        "expired": expired,
        "expiring": expiring,
        "old_keys": old_keys,
    }


def run_health_dashboard(vault: Dict[str, Any]) -> None:
    print_header("Vault Health")
    if not vault:
        note("Vault is empty. Nothing to analyze.")
        pause()
        return

    h = collect_health(vault)
    note(f"Saved: {h['n_pwd']} passwords  ·  {h['n_api']} API keys\n")

    def section(title: str, items: List[Any], report: Callable, ok_msg: str) -> None:
        if items:
            report(f"{title} ({len(items)})")
            for item in items:
                print(f"      {item}")
        else:
            ok(ok_msg)
        print()

    section("Weak passwords", h["weak"], err, "No weak passwords detected.")
    section("Reused secrets", [", ".join(s) for s in h["duplicates"].values()], warn,
            "No duplicate passwords/keys detected.")
    section("Expired API keys", h["expired"], err, "No expired API keys.")
    section(f"API keys expiring within {EXPIRY_WARN_DAYS} days", h["expiring"], warn,
            "No API keys expiring soon.")
    section(f"API keys older than {ROTATE_AFTER_DAYS} days (consider rotating)", h["old_keys"],
            warn, "No API keys overdue for rotation.")
    pause()


# ---------------------------------------------------------------------------
# Backup / Restore / Change Master / Export
# ---------------------------------------------------------------------------
def backup_vault() -> None:
    docs_dir = USER_HOME / "Documents"
    backup_dir = docs_dir if docs_dir.is_dir() else USER_HOME
    default_name = backup_dir / f"vault_backup_{datetime.now():%Y%m%d_%H%M}.enc"
    note(f"Default: {default_name}")
    backup_path = Path(prompt("Path/filename for the backup (Enter = default): ").strip() or default_name)
    if backup_path.exists() and not confirm(f"'{backup_path}' exists. Overwrite?"):
        warn("Backup cancelled.")
        return
    try:
        secure_write(backup_path, VAULT_FILE.read_bytes())
        save_config(last_backup=datetime.now().isoformat(timespec="seconds"))
        ok(f"Encrypted backup created at '{backup_path}'.")
        note("Keep it safe — it is protected only by your master password.")
    except Exception as e:
        err(f"Backup failed: {e}")


def restore_vault(session: Session, current_vault: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    backup_path = Path(prompt("Path to encrypted backup file: ").strip())
    if not backup_path.exists():
        err("File does not exist.")
        return None

    try:
        data = backup_path.read_bytes()
        backup_pass = secret_prompt("Master password used for that backup: ")
        with Spinner("Decrypting"):
            restored = decrypt_any_backup(data, backup_pass)
    except InvalidToken:
        err("Failed to decrypt backup! Wrong password or file corrupted.")
        return None
    except Exception as e:
        err(f"Restore failed: {e}")
        return None

    mode = prompt(
        f"Found {len(restored)} entries. (M)erge into current vault or (R)eplace it? [M/R]: "
    ).strip().lower()
    if mode == "r":
        if not confirm("This REPLACES everything currently in your vault. Continue?"):
            warn("Restore cancelled.")
            return None
        new_vault = restored
    else:
        new_vault = dict(restored)
        new_vault.update(current_vault)

    save_vault(session, new_vault)
    ok(f"Vault restored! It now holds {len(new_vault)} entries.")
    return new_vault


def change_master_password(session: Session, vault: Dict[str, Any]) -> Session:
    if not reauthenticate(session):
        err("Master password not confirmed. Nothing was changed.")
        return session
    new_pass = ask_new_master_password()
    shutil.copy2(VAULT_FILE, VAULT_FILE.with_suffix(".enc.bak"))
    trash = load_trash(session)

    new_sess = new_session(new_pass)
    save_vault(new_sess, vault)
    save_trash(new_sess, trash)
    ok("Master password changed.")
    warn(f"Previous vault kept as vault.enc.bak in {APP_DIR}.\n"
         f"Once the new password works, DELETE it.")
    return new_sess


def export_vault(session: Session, vault: Dict[str, Any]) -> None:
    """Create an encrypted export file (can be imported later)."""
    default = Path.home() / "Documents" / f"vault_export_{datetime.now():%Y%m%d_%H%M}.pvex"
    note(f"Default: {default}")
    path = Path(prompt("Export path (Enter = default): ").strip() or default)
    if path.exists() and not confirm(f"'{path}' exists. Overwrite?"):
        warn("Export cancelled.")
        return

    data = EXPORT_MAGIC + pack_container(session, vault)
    try:
        secure_write(path, data)
        ok(f"Encrypted export written to '{path}'.")
        note("This file can only be opened with the current master password.")
    except Exception as e:
        err(f"Export failed: {e}")


# ---------------------------------------------------------------------------
# Add / Edit
# ---------------------------------------------------------------------------
def add_password(vault: Dict[str, Any], session: Session) -> None:
    website = prompt("Website name (e.g., Netflix): ").strip()
    if not website:
        return
    if website in vault and not confirm(f"'{website}' already exists. Overwrite it?"):
        warn("Cancelled.")
        return
    username = prompt(f"Username/Email for {website}: ").strip()

    pwd_choice = prompt("(G)enerate a password or (T)ype your own? [G/T]: ").strip().lower()
    generated = False
    if pwd_choice == "t":
        new_pass = secret_prompt(f"Enter password for {website}: ")
        print(f"  Strength: {strength_line(new_pass)}")
        if check_password_strength(new_pass)[0] == "Weak" and not confirm(
                "Are you sure you want to save a weak password?"):
            err("Aborted.")
            return
    else:
        new_pass = generate_random_password()
        generated = True

    # Duplicate check
    dups = find_duplicate_secret(vault, new_pass, exclude=website)
    if dups:
        warn(f"This secret is already used by: {', '.join(dups)}")
        if not confirm("Save it anyway?"):
            return

    vault[website] = {"type": "password", "username": username, "password": new_pass}
    save_vault(session, vault)
    ok(f"Saved {website} to the vault.")
    if generated:
        note("A strong password was generated for you.")
        copy_with_autoclear(new_pass)


def add_api_key(vault: Dict[str, Any], session: Session) -> None:
    name = prompt("API key name (e.g., OpenAI - personal, Tavily): ").strip()
    if not name:
        return
    if name in vault and not confirm(f"'{name}' already exists. Overwrite it?"):
        warn("Cancelled.")
        return

    api_key = secret_prompt("Paste the API key (hidden): ").strip()
    if not api_key:
        err("No key entered. Aborted.")
        return

    # Duplicate check
    dups = find_duplicate_secret(vault, api_key, exclude=name)
    if dups:
        warn(f"This secret is already used by: {', '.join(dups)}")
        if not confirm("Save it anyway?"):
            return

    notes = prompt("Notes: what is it used for / which project? (optional): ").strip()
    env_name = prompt("Environment variable for `vault run` (optional, e.g. OPENAI_API_KEY): ").strip()
    if env_name and not ENV_NAME_RE.match(env_name):
        warn("That isn't a valid environment variable name, so it was not saved.")
        env_name = ""
    expires = ask_optional_date("Expiry date YYYY-MM-DD (optional, Enter to skip): ")

    vault[name] = {
        "type": "api_key",
        "api_key": api_key,
        "notes": notes,
        "created": date.today().isoformat(),
        "expires": expires,
    }
    if env_name:
        vault[name]["env"] = env_name
    save_vault(session, vault)
    ok(f"Saved API key '{name}' to the vault.")


def _ask_keep(label: str, current: str) -> str:
    shown = current if current else G_EMPTY
    value = prompt(f"{label} {MUTED}[{shown}]{RST}: ").strip()
    if value == "":
        return current
    if value == "-":
        return ""
    return value


def edit_entry(vault: Dict[str, Any], session: Session, name: str) -> bool:
    entry = vault[name]
    if not isinstance(entry, dict):
        entry = {"type": "password", "username": "", "password": entry}
    entry = dict(entry)
    is_api = entry_type(entry) == "api_key"

    print_header(f"Edit · {name}")
    note("Press Enter to keep a value, or type - to clear it.\n")

    new_name = prompt(f"Name {MUTED}[{name}]{RST}: ").strip() or name
    if new_name != name and new_name in vault:
        err(f"'{new_name}' already exists. Nothing was changed.")
        return False

    generated = False
    if is_api:
        entry["notes"] = _ask_keep("Notes", entry.get("notes", ""))
        env = _ask_keep("Environment variable", entry.get("env", ""))
        if env and not ENV_NAME_RE.match(env):
            warn("Invalid environment variable name; keeping the old one.")
            env = entry.get("env", "")
        entry["env"] = env
        raw = prompt(f"Expiry YYYY-MM-DD {MUTED}[{entry.get('expires') or G_EMPTY}]{RST}: ").strip()
        if raw == "-":
            entry["expires"] = ""
        elif raw:
            parsed = parse_date(raw)
            if parsed is None:
                err("Please use YYYY-MM-DD. Nothing was changed.")
                return False
            entry["expires"] = parsed.isoformat()
        if prompt("Replace the API key itself? [y/N]: ").strip().lower() == "y":
            new_key = secret_prompt("Paste the new API key (hidden): ").strip()
            if new_key:
                dups = find_duplicate_secret(vault, new_key, exclude=name)
                if dups:
                    warn(f"This secret is already used by: {', '.join(dups)}")
                    if not confirm("Save it anyway?"):
                        return False
                entry["api_key"] = new_key
                entry["created"] = date.today().isoformat()
    else:
        entry["username"] = _ask_keep("Username/Email", entry.get("username", ""))
        entry["url"] = _ask_keep("Website URL", entry.get("url", ""))
        choice = prompt("Password: (K)eep, (G)enerate new, (T)ype new [K/G/T]: ").strip().lower()
        if choice == "g":
            entry["password"] = generate_random_password()
            generated = True
        elif choice == "t":
            new_pass = secret_prompt("Enter the new password: ")
            if new_pass:
                print(f"  Strength: {strength_line(new_pass)}")
                if check_password_strength(new_pass)[0] == "Weak" and not confirm("Save this weak password?"):
                    err("Nothing was changed.")
                    return False
                dups = find_duplicate_secret(vault, new_pass, exclude=name)
                if dups:
                    warn(f"This secret is already used by: {', '.join(dups)}")
                    if not confirm("Save it anyway?"):
                        return False
                entry["password"] = new_pass

    for key in ("url", "notes", "env"):
        if key in entry and not entry[key]:
            del entry[key]

    rebuilt = [(new_name if k == name else k, entry if k == name else v) for k, v in vault.items()]
    vault.clear()
    vault.update(rebuilt)
    save_vault(session, vault)
    ok(f"Saved changes to '{new_name}'.")
    if generated:
        note("A new strong password was generated.")
        copy_with_autoclear(entry["password"])
    return True


# ---------------------------------------------------------------------------
# CSV Import
# ---------------------------------------------------------------------------
CSV_ALIASES = {
    "name": ("name", "title", "login_name"),
    "url": ("url", "login_uri", "website", "web site", "origin"),
    "username": ("username", "login_username", "user", "login", "email"),
    "password": ("password", "login_password", "pass"),
    "notes": ("note", "notes"),
}


def _csv_pick(row: Dict[str, str], field: str) -> str:
    for key in CSV_ALIASES[field]:
        value = (row.get(key) or "").strip()
        if value:
            return value
    return ""


def shred_file(path: Path) -> bool:
    try:
        size = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
        path.unlink()
        return True
    except OSError:
        return False


def import_csv(vault: Dict[str, Any], session: Session, path: Path, on_conflict: str = "skip", offer_delete: bool = True) -> int:
    path = Path(str(path).strip().strip('"').strip("'"))
    if not path.is_file():
        err(f"File not found: {path}")
        return 0

    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = [{(k or "").strip().lower(): (v or "") for k, v in raw.items() if k} for raw in reader]
            headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        err(f"Couldn't read that file as CSV: {e}")
        return 0

    if not any(h in CSV_ALIASES["password"] for h in headers):
        err("Couldn't find a password column. Columns found: " + (", ".join(headers) or "none"))
        return 0

    added = skipped = no_password = other_types = overwritten = 0
    for number, row in enumerate(rows, start=1):
        if row.get("type", "login").strip().lower() not in ("", "login"):
            other_types += 1
            continue
        password = _csv_pick(row, "password")
        if not password:
            no_password += 1
            continue
        url = _csv_pick(row, "url")
        name = _csv_pick(row, "name") or hostname_of(url) or f"Imported {number}"

        if name in vault:
            if on_conflict == "skip":
                skipped += 1
                continue
            if on_conflict == "rename":
                i = 2
                while f"{name} ({i})" in vault:
                    i += 1
                name = f"{name} ({i})"
            else:
                overwritten += 1

        entry = {"type": "password", "username": _csv_pick(row, "username"), "password": password}
        if url:
            entry["url"] = url
        notes = _csv_pick(row, "notes")
        if notes:
            entry["notes"] = notes
        vault[name] = entry
        added += 1

    if added or overwritten:
        save_vault(session, vault)
    ok(f"Imported {added} login{'s' if added != 1 else ''}.")
    details = []
    if skipped:
        details.append(f"{skipped} skipped (name already in the vault)")
    if overwritten:
        details.append(f"{overwritten} overwritten")
    if no_password:
        details.append(f"{no_password} had no password")
    if other_types:
        details.append(f"{other_types} non-login items ignored")
    if details:
        note(", ".join(details))

    if added and offer_delete:
        print()
        warn("That CSV file holds your passwords in PLAIN TEXT.")
        if confirm("Overwrite and delete it now?"):
            if shred_file(path):
                ok("File deleted.")
            else:
                err("Couldn't delete it. Please delete it yourself.")
        else:
            warn("Please delete it as soon as you can.")
    return added


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
_WORDS_TEXT = """
acorn amber angel anchor apple april apron arrow aspen atlas autumn bacon badge badger baker ballet
bamboo banjo banner barley barrel basil basket beach beacon beetle bellow bench berry birch biscuit
bishop blanket blossom bobcat bonus border bottle boulder bounce bramble branch brass breeze brick
bridge brisk bronze brook brush bubble bucket buffalo bundle burrow butter button cabbage cabin cactus
camel candle cannon canoe canvas canyon captain caramel cargo carpet carrot carton cashew castle cattle
caviar cedar celery cellar cereal chair chalk chapel charm cheese cherry chess chicken chorus cinder
cipher circle citrus clever cliff clock cloud clover cluster cobalt cocoa coffee comet compass cookie
copper coral cotton cousin cowboy cradle crater crayon creek cricket crimson crown crystal cuckoo curtain
cushion custard cymbal dagger daisy dancer dandelion dapple dawn delta denim desert diamond diner dinner
dolphin donkey doodle dozen dragon drawer dream drift drizzle drum dumpling dune dusk eagle earth ebony
echo eclipse elbow elder ember emerald engine escape fable fabric falcon farmer feather ferry fiddle
field figure filter finch flame flannel flint flurry flute folder forest fossil fountain frigate frost
fudge gadget galaxy gallop gander garden garlic garnet gazelle gentle geyser ginger gizmo glacier globe
goblin gopher gourd granite grape gravel gravy grove guitar gumdrop habit hamlet hammer harbor harvest
hawk hazel hedge helmet hermit heron hickory hobby hollow honey horizon hornet hotel hunter hurdle husky
icicle igloo iguana indigo inkwell island ivory jacket jaguar jasper jelly jester jigsaw jockey jolly
jumper jungle kayak kebab kernel kettle kiosk kitten knight koala ladder lagoon lantern lark lasso latte
lava lemon lemur lentil lettuce lilac linen lizard llama lobster locket locust lotus lumber lunar lynx
macaw magnet magpie mango maple marble meadow mellow melon mercury merlin meteor mingle mirror mitten
mocha mohawk monkey mosaic moss mountain muffin mulberry mustard nacho napkin nectar needle nickel noodle
nomad nugget nutmeg oasis oatmeal ocean olive onion onyx opal orange orbit orchid osprey otter outpost
oval oyster paddle paddock pagoda palace pancake panda panther papaya parade parrot pasta pastry patrol
peach peanut pearl pebble pelican pencil pepper petal pewter piano pickle pigeon pillow pilot pinecone
pirate pixel plank planet plaza plum pocket pollen polka pond poncho poplar porch potato pouch prairie
pretzel pudding puffin pumpkin puzzle pylon quail quartz quill quiver rabbit raccoon radar radish rafter
rainbow raisin rampart ranger raven ravine relic rhino ribbon ridge river robin rocket rodeo rooster
rubber saber saddle safari saffron sailor salad salmon salsa sandal sapphire sausage scarf scooter scout
seagull season sequoia shadow shell shovel shrimp signal silver sketch skiff skylark slate sleeve slipper
smoke snail sneaker soccer socket sorbet sparrow spatula spice spider spinach spirit sponge sprout spruce
squirrel stable stallion starfish statue steam sticker stirrup stone storm stream summer sunbeam sundae
sunset swallow swamp sweater syrup tablet tadpole tailor talent tango tapir tartan teacup teapot tempo
temple tennis thimble thistle thorn thunder ticket tiger timber toffee tomato topaz tortoise totem toucan
tractor trader trailer trellis tricycle trophy trumpet truffle tulip tundra tunnel turnip turtle tweed
umbrella unicorn utensil valley vanilla velvet vessel village violet vortex voyage waffle wagon wallet
walnut walrus wander warbler wasabi weasel whale wheat whisper whistle wicker willow windmill window
winter wizard wolf wombat yellow yodel yogurt zebra zephyr zipper
"""
WORDS = sorted(set(_WORDS_TEXT.split()))


def generate_passphrase(words: int = 6, sep: str = "-") -> str:
    if not isinstance(words, int) or not 3 <= words <= 32:
        raise ValueError("word count must be between 3 and 32")
    if not isinstance(sep, str) or len(sep) > 16:
        raise ValueError("separator must be a string of at most 16 characters")
    return sep.join(secrets.choice(WORDS) for _ in range(words))


def cmd_gen(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="vault gen",
        description="Generate a password or passphrase. Does not need your master password.",
    )
    parser.add_argument("-n", "--length", type=int, default=20, help="password length (default 20)")
    parser.add_argument("--no-symbols", action="store_true", help="letters and digits only")
    parser.add_argument("--words", type=int, metavar="N", help="make a passphrase of N words instead")
    parser.add_argument("--sep", default="-", help="separator between passphrase words (default -)")
    parser.add_argument("--show", action="store_true", help="print it instead of copying it")
    args = parser.parse_args(argv)

    if args.words is not None:
        if not 3 <= args.words <= 12:
            parser.error("--words must be between 3 and 12")
        secret = generate_passphrase(args.words, args.sep)
        bits = args.words * math.log2(len(WORDS))
        info = f"{args.words} words from a list of {len(WORDS)} (~{bits:.0f} bits)"
    else:
        if not 8 <= args.length <= 128:
            parser.error("--length must be between 8 and 128")
        secret = generate_random_password(args.length, symbols=not args.no_symbols)
        pool = 62 + (len(string.punctuation) if not args.no_symbols else 0)
        info = f"{args.length} characters (~{args.length * math.log2(pool):.0f} bits)"

    print()
    note(info)
    if args.words is None:
        print(f"  Strength: {strength_line(secret)}")
    if args.show:
        print(f"\n  {INV} {secret} {RST}\n")
    else:
        copy_with_autoclear(secret, block_if_needed=True)
        print()
    return 0


# ---------------------------------------------------------------------------
# vault run
# ---------------------------------------------------------------------------
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def to_env_name(name: str) -> str:
    derived = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper() or "SECRET"
    return derived if not derived[0].isdigit() else "_" + derived


def cmd_run(argv: List[str]) -> int:
    if "--" not in argv:
        err("Usage: vault run NAME [NAME...] -- COMMAND [ARGS...]\n"
            "Example: vault run openai tavily -- python app.py")
        return 2
    split = argv.index("--")
    specs, command = argv[:split], argv[split + 1:]
    if not specs or not command:
        err("Usage: vault run NAME [NAME...] -- COMMAND [ARGS...]")
        return 2

    session, vault = unlock_vault()
    if vault is None:
        return 1

    injected: Dict[str, str] = {}
    for spec in specs:
        term, _, forced = spec.rpartition("=")
        if not term or not ENV_NAME_RE.match(forced):
            term, forced = spec, ""
        site = resolve_name(vault, term)
        if site is None:
            return 1
        entry = vault[site]
        var = forced or (entry.get("env") if isinstance(entry, dict) else "") or to_env_name(site)
        if var in injected:
            err(f"Two entries would both set {var}. Use NAME=ENV_VAR to give one a different name.")
            return 1
        if entry_type(entry) == "api_key":
            days = days_until_expiry(entry)
            if days is not None and days < 0:
                warn(f"'{site}' expired {-days} day(s) ago.")
        injected[var] = entry_secret(entry)

    print(f"{MUTED}  Injecting {', '.join(injected)} into: {' '.join(command)}{RST}", file=sys.stderr)
    env = os.environ.copy()
    env.update(injected)
    exe = shutil.which(command[0]) or command[0]
    try:
        return subprocess.run([exe] + command[1:], env=env).returncode
    except FileNotFoundError:
        err(f"Command not found: {command[0]}")
        return 127
    except KeyboardInterrupt:
        return 130


# ---------------------------------------------------------------------------
# Config command
# ---------------------------------------------------------------------------
def cmd_config(argv: List[str]) -> int:
    print_header("Configuration")
    cfg = load_config()
    print(f"  Clipboard timeout : {cfg.get('clipboard_timeout', DEFAULT_CLIPBOARD_TIMEOUT)} s")
    print(f"  Show seconds      : {cfg.get('show_seconds', DEFAULT_SHOW_SECONDS)} s")
    print(f"  Auto-lock         : {cfg.get('auto_lock_seconds', DEFAULT_AUTO_LOCK_SECONDS)} s")
    print(f"  Theme             : {cfg.get('theme', 'dark')}")
    print()

    if not confirm("Change settings?"):
        return 0

    try:
        ct = prompt(f"Clipboard timeout in seconds [{cfg.get('clipboard_timeout', DEFAULT_CLIPBOARD_TIMEOUT)}]: ").strip()
        if ct:
            save_config(clipboard_timeout=max(5, int(ct)))

        ss = prompt(f"Show seconds [{cfg.get('show_seconds', DEFAULT_SHOW_SECONDS)}]: ").strip()
        if ss:
            save_config(show_seconds=max(3, int(ss)))

        al = prompt(f"Auto-lock seconds [{cfg.get('auto_lock_seconds', DEFAULT_AUTO_LOCK_SECONDS)}]: ").strip()
        if al:
            save_config(auto_lock_seconds=max(60, int(al)))

        ok("Settings saved. They will take effect on next launch.")
    except ValueError:
        err("Invalid number.")
    return 0


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------
def doctor_json_summary() -> int:
    failures = _read_attempts().get("count", 0)
    last = load_config().get("last_backup")
    problems = []
    if not VAULT_FILE.exists():
        problems.append("vault file is missing")
    if failures:
        problems.append(f"{failures} failed login attempts recorded")
    if not last:
        problems.append("no backup recorded")
    result = {
        "version": VERSION,
        "data_dir": str(APP_DIR),
        "vault_exists": VAULT_FILE.exists(),
        "failed_attempts": failures,
        "last_backup": last,
        "problems": problems,
    }
    print(json.dumps(result))
    return 1 if problems else 0


def cmd_doctor(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="vault doctor", description="Check the vault setup.")
    parser.add_argument("--deep", action="store_true",
                        help="also unlock the vault and check expired keys, weak/reused passwords")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable diagnostic summary")
    args = parser.parse_args(argv)
    if args.json:
        return doctor_json_summary()

    problems = 0

    def bad(msg: str) -> None:
        nonlocal problems
        problems += 1
        warn(msg)

    print()
    frozen = getattr(sys, "frozen", False)
    runtime = "standalone exe" if frozen else f"Python {sys.version.split()[0]}"
    note(f"vault {VERSION}  {G_DOT}  {runtime}  {G_DOT}  {sys.platform}")
    note(f"Data folder: {APP_DIR}\n")

    if not VAULT_FILE.exists():
        bad("No vault file yet. Run `vault` once to create it.")
    else:
        with open(VAULT_FILE, "rb") as f:
            head = f.read(_HEADER_LEN)
        if head.startswith(VAULT_MAGIC) and len(head) == _HEADER_LEN:
            n_log2, r, p = head[len(VAULT_MAGIC) + 16:]
            ok(f"Vault file found (scrypt N=2^{n_log2}, r={r}, p={p})")
            if n_log2 < SCRYPT_N_LOG2:
                bad(f"Its key-stretching is weaker than the current default (2^{SCRYPT_N_LOG2}). "
                    "Changing the master password re-encrypts it with the newer settings.")
        else:
            bad("Vault is in the old format. Unlock it once (run `vault`) to upgrade it.")

    if os.name != "nt":
        for path, want in ((APP_DIR, 0o700), (VAULT_FILE, 0o600)):
            if path.exists() and stat.S_IMODE(path.stat().st_mode) != want:
                bad(f"{path} should have permissions {oct(want)[2:]}")

    leftovers = []
    has_v2 = VAULT_FILE.exists() and VAULT_FILE.read_bytes()[:len(VAULT_MAGIC)] == VAULT_MAGIC
    for fname in sorted(os.listdir(APP_DIR)):
        if fname.endswith((".bak", ".tmp")) or (fname == "salt.key" and has_v2):
            age = int((time.time() - os.path.getmtime(APP_DIR / fname)) / 86400)
            leftovers.append(f"{fname} ({age}d old)")
    if leftovers:
        bad("Leftover files that use older or weaker protection. Delete them once you've confirmed\n"
            "everything works: " + ", ".join(leftovers))
    else:
        ok("No leftover .bak / .tmp files")

    failures = _read_attempts().get("count", 0)
    if failures:
        bad(f"{failures} failed login attempt(s) recorded since the last successful unlock")
    else:
        ok("No failed login attempts recorded")

    last = load_config().get("last_backup")
    if not last:
        bad("You haven't made a backup with this version yet (menu: Backup / restore)")
    else:
        try:
            days = (datetime.now() - datetime.fromisoformat(last)).days
            if days > BACKUP_STALE_DAYS:
                bad(f"Last backup was {days} days ago")
            else:
                ok(f"Last backup {days} day{'s' if days != 1 else ''} ago")
        except ValueError:
            bad("Backup date in the config is unreadable")

    if HAS_PYPERCLIP:
        try:
            pyperclip.paste()
            ok("Clipboard access works (pyperclip)")
        except Exception as e:
            bad(f"pyperclip available but failed: {e}")
    else:
        if os.name == "nt":
            ok("pyperclip not installed – will try Windows clip.exe as fallback")
        else:
            bad("pyperclip not installed – clipboard features limited")

    if load_config().get("completion"):
        note(f"{G_DOT} Tab completion is ON: entry NAMES (not secrets) are kept in plain text in names.txt")

    if args.deep:
        print()
        session, vault = unlock_vault()
        if vault is None:
            return 1
        h = collect_health(vault)
        ok(f"Unlocked: {h['n_pwd']} passwords, {h['n_api']} API keys, {len(load_trash(session))} in trash")
        for title, items in (("Weak passwords", h["weak"]), ("Reused secrets", list(h["duplicates"].values())),
                             ("Expired API keys", h["expired"]), ("API keys expiring soon", h["expiring"]),
                             ("API keys due for rotation", h["old_keys"])):
            if items:
                flat = [", ".join(i) if isinstance(i, list) else i for i in items]
                bad(f"{title}: " + "; ".join(flat))
            else:
                ok(f"{title}: none")

    print()
    if problems:
        warn(f"{problems} thing{'s' if problems != 1 else ''} to look at.")
    else:
        ok("Everything looks good.")
    print()
    return 0


# ---------------------------------------------------------------------------
# PowerShell completion
# ---------------------------------------------------------------------------
PS_COMPLETION = r'''
# vault tab-completion. Add to your profile with:
#   New-Item -ItemType File -Force $PROFILE | Out-Null; vault completion powershell | Add-Content $PROFILE
Register-ArgumentCompleter -Native -CommandName vault -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = 'get', 'gen', 'edit', 'restore', 'run', 'import', 'export', 'config', 'doctor', 'completion'
  $file = Join-Path $env:USERPROFILE '.local_password_vault\names.txt'
  $names = @()
  if (Test-Path -LiteralPath $file) { $names = @(Get-Content -LiteralPath $file -Encoding UTF8) }
  $pool = $names
  if ($commandAst.CommandElements.Count -le 2) { $pool = $commands + $names }
  $pool | Where-Object { $_ -and $_.StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase) } |
    ForEach-Object {
      $text = $_
      if ($text -match '[\s''"`$&();|<>]') { $text = "'" + $text.Replace("'", "''") + "'" }
      [System.Management.Automation.CompletionResult]::new($text, $_, 'ParameterValue', $_)
    }
}
'''


def sync_names_index(vault_data: Dict[str, Any]) -> None:
    if not load_config().get("completion"):
        return
    try:
        names = "\n".join(sorted((n.replace("\n", " ") for n in vault_data), key=str.lower))
        secure_write(NAMES_FILE, names.encode("utf-8"))
    except OSError:
        pass


def cmd_completion(argv: List[str]) -> int:
    sub = argv[0] if argv else "status"
    if sub == "powershell":
        print(PS_COMPLETION.strip("\n"))
        return 0

    if sub == "enable":
        warn("Tab completion needs your entry NAMES (never the secrets) in a plain-text file:\n"
             f"{NAMES_FILE}\n"
             "Anyone who can read your user folder could then see which services you use.")
        if not confirm("Enable tab completion?"):
            return 0
        session, vault = unlock_vault()
        if vault is None:
            return 1
        save_config(completion=True)
        sync_names_index(vault)
        ok("Tab completion enabled. One more step, in PowerShell:")
        note("New-Item -ItemType File -Force $PROFILE | Out-Null; vault completion powershell | Add-Content $PROFILE\n"
             "Then restart PowerShell. If it says scripts are disabled, run once:\n"
             "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned")
        return 0

    if sub == "disable":
        save_config(completion=False)
        try:
            NAMES_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        ok("Tab completion disabled and names.txt deleted.")
        note("You can also remove the block from your PowerShell profile ($PROFILE).")
        return 0

    if sub == "status":
        on = load_config().get("completion")
        note(f"Tab completion is {'ON' if on else 'OFF'}.  Usage: vault completion [enable|disable|powershell]")
        return 0

    err("Usage: vault completion [enable | disable | powershell | status]")
    return 2


# ---------------------------------------------------------------------------
# Interactive Menu
# ---------------------------------------------------------------------------
def status_line(user_name: str, vault: Dict[str, Any]) -> str:
    h = collect_health(vault)
    n_keys = len(h["expired"]) + len(h["expiring"])
    n_pwd_issues = len(h["weak"]) + len(h["duplicates"])
    alerts = []
    if n_keys:
        alerts.append(f"{n_keys} API key{'s' if n_keys != 1 else ''} need attention")
    if n_pwd_issues:
        alerts.append(f"{n_pwd_issues} password issue{'s' if n_pwd_issues != 1 else ''}")

    entries = f"{len(vault)} entr{'y' if len(vault) == 1 else 'ies'}"
    left = f"{BOLD}vault{RST}{MUTED}  {G_DOT}  {user_name}  {G_DOT}  {entries}{RST}"
    if alerts:
        right = f"{WARN}{G_WARN}  {' · '.join(alerts)}{RST}"
    else:
        right = f"{OK}{G_OK}  all clear{RST}"

    left_plain = f"vault  ·  {user_name}  ·  {entries}"
    right_plain = f"!  {' · '.join(alerts)}" if alerts else "✓  all clear"
    pad = term_width() - 4 - len(left_plain) - len(right_plain)
    if pad >= 2:
        return f"  {left}{' ' * pad}{right}"
    return f"  {left}\n  {right}"


def print_menu(user_name: str, vault: Dict[str, Any]) -> None:
    print()
    print(status_line(user_name, vault))
    print()
    print(f"  {MUTED}{G_H * (term_width() - 4)}{RST}")
    print()

    def group(title: str, items: List[Tuple[str, str]]) -> None:
        print(f"  {MUTED}{title}{RST}")
        for num, label in items:
            print(f"    {HEAD}{num:>2}{RST}   {label}")
        print()

    group("ADD", [
        ("1", "Add / update password"),
        ("2", "Add / update API key"),
        ("3", "Import from CSV"),
    ])
    group("ACCESS", [
        ("4", "Get a secret"),
        ("5", "Edit an entry"),
        ("6", "Delete an entry"),
        ("7", "Trash (restore deleted)"),
    ])
    group("MAINTAIN", [
        ("8", "Health check"),
        ("9", "Backup / restore / export"),
        ("10", "Change master password"),
        ("11", "Settings (timeouts)"),
    ])
    print(f"    {HEAD}{'0':>2}{RST}   Exit")
    print()


def run_vault_app() -> int:
    clear_screen()
    user_name = get_or_set_username()

    print_banner()
    note(f"Welcome back, {user_name}.\n")

    session, vault = unlock_vault()
    if vault is None:
        return 1

    lock = AutoLock()

    try:
        while True:
            clear_screen()
            print_menu(user_name, vault)

            lock.arm()
            choice = input(f"  {ACCENT}{G_PROMPT}{RST} ").strip()
            lock.disarm()

            if lock.locked:
                if not reauthenticate(session):
                    wipe_screen()
                    err("Could not unlock. Closing the vault.")
                    return 1
                lock.locked = False
                continue

            if choice == "1":
                print_header("Add / Update Password")
                add_password(vault, session)
                pause()

            elif choice == "2":
                print_header("Add / Update API Key")
                add_api_key(vault, session)
                pause()

            elif choice == "3":
                print_header("Import from CSV")
                note("Works with exports from Chrome, Edge, Firefox and Bitwarden.\n")
                path = prompt("Path to the CSV file (you can drag the file here): ")
                if path.strip():
                    import_csv(vault, session, Path(path))
                pause()

            elif choice == "4":
                site = pick_entry(vault, "Get a Secret")
                if site:
                    entry = vault[site]
                    if entry_type(entry) == "api_key" and not reauthenticate(session):
                        err("Access denied.")
                        pause()
                        continue
                    mode = prompt(f"[C]opy to clipboard or [S]how for {SHOW_SECONDS}s? [C/s]: ").strip().lower()
                    deliver_secret(site, entry, show=(mode == "s"))
                    pause()

            elif choice == "5":
                site = pick_entry(vault, "Edit an Entry")
                if site:
                    if entry_type(vault[site]) == "api_key" and not reauthenticate(session):
                        err("Access denied.")
                    else:
                        edit_entry(vault, session, site)
                    pause()

            elif choice == "6":
                site = pick_entry(vault, "Delete an Entry", allow_search=False)
                if site and confirm(f"Delete '{site}'? It stays in the trash for {TRASH_DAYS} days."):
                    trash_add(session, site, vault.pop(site))
                    save_vault(session, vault)
                    ok(f"Moved '{site}' to the trash.")
                    pause()
                elif site:
                    warn("Deletion cancelled.")
                    pause()

            elif choice == "7":
                print_header("Trash")
                print(f"    {HEAD}{'1':>2}{RST}   Restore a deleted entry")
                print(f"    {HEAD}{'2':>2}{RST}   Empty the trash\n")
                sub = prompt("Choose an option [1-2]: ").strip()
                print()
                if sub == "1":
                    restore_from_trash(vault, session)
                elif sub == "2":
                    empty_trash(session)
                pause()

            elif choice == "8":
                run_health_dashboard(vault)

            elif choice == "9":
                print_header("Backup / Restore / Export")
                print(f"    {HEAD}{'1':>2}{RST}   Create encrypted backup")
                print(f"    {HEAD}{'2':>2}{RST}   Restore from backup")
                print(f"    {HEAD}{'3':>2}{RST}   Export encrypted archive\n")
                sub = prompt("Choose an option [1-3]: ").strip()
                print()
                if sub == "1":
                    backup_vault()
                elif sub == "2":
                    updated = restore_vault(session, vault)
                    if updated is not None:
                        vault = updated
                elif sub == "3":
                    export_vault(session, vault)
                pause()

            elif choice == "10":
                print_header("Change Master Password")
                session = change_master_password(session, vault)
                pause()

            elif choice == "11":
                cmd_config([])
                pause()

            elif choice == "0":
                clear_screen()
                print()
                note(f"Vault locked. Have a great day, {user_name}.")
                note(f"Thank you for using software developed by {CREATOR_NAME}.\n")
                return 0
            else:
                err("Invalid choice. Please select 0 to 11.")
                time.sleep(1)
    finally:
        lock.stop()


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def run_quick_lookup(query_words: List[str], show: bool = False, list_only: bool = False,
                     json_output: bool = False) -> int:
    session, vault = unlock_vault()
    if vault is None:
        return 1

    if list_only:
        if not vault:
            if json_output:
                print("[]")
                return 0
            note("Vault is empty.")
        else:
            if json_output:
                print(json.dumps(sorted(vault, key=str.lower)))
                return 0
            print()
            print_table(vault, sorted(vault, key=str.lower))
            print()
        return 0

    term = " ".join(query_words).strip()
    print()
    site = resolve_name(vault, term)
    if site is None:
        return 1

    print_table(vault, [site])
    deliver_secret(site, vault[site], show=show, quick=True)
    print()
    return 0


def cmd_get(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="vault get", description="Look up one entry and copy its secret.")
    parser.add_argument("query", nargs="+", help="name (or part of it)")
    parser.add_argument("-s", "--show", action="store_true", help=f"show for {SHOW_SECONDS}s instead of copying")
    args = parser.parse_args(argv)
    return run_quick_lookup(args.query, show=args.show)


def cmd_list(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="vault list", description="List entry names without secrets.")
    parser.add_argument("--json", action="store_true", help="emit a JSON array of names")
    args = parser.parse_args(argv)
    return run_quick_lookup([], list_only=True, json_output=args.json)


def cmd_edit(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="vault edit", description="Change one field of an entry.")
    parser.add_argument("query", nargs="*", help="name (or part of it); leave out to pick from a list")
    args = parser.parse_args(argv)

    session, vault = unlock_vault()
    if vault is None:
        return 1
    if not vault:
        note("Vault is empty.")
        return 0
    if args.query:
        site = resolve_name(vault, " ".join(args.query), action="Edit")
    else:
        site = pick_entry(vault, "Edit an Entry")
    if site is None:
        return 1
    return 0 if edit_entry(vault, session, site) else 1


def cmd_delete(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="vault delete",
        description=f"Move an entry to encrypted trash for {TRASH_DAYS} days.",
    )
    parser.add_argument("query", nargs="+", help="name (or part of it)")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = parser.parse_args(argv)

    session, vault = unlock_vault()
    if vault is None:
        return 1
    site = resolve_name(vault, " ".join(args.query), action="Delete")
    if site is None:
        return 1
    if not args.yes and not confirm(f"Delete '{site}'? It stays in the trash for {TRASH_DAYS} days."):
        warn("Deletion cancelled.")
        return 0

    trash_add(session, site, vault.pop(site))
    save_vault(session, vault)
    ok(f"Moved '{site}' to the trash.")
    return 0


def cmd_restore(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="vault restore",
        description=f"Bring back an entry you deleted (kept for {TRASH_DAYS} days).")
    parser.add_argument("query", nargs="*", help="name (or part of it) to look for in the trash")
    parser.add_argument("--empty", action="store_true", help="permanently empty the trash")
    args = parser.parse_args(argv)

    session, vault = unlock_vault()
    if vault is None:
        return 1
    print()
    if args.empty:
        empty_trash(session)
        return 0
    return 0 if restore_from_trash(vault, session, " ".join(args.query)) else 1


def cmd_import(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="vault import",
        description="Import logins from a Chrome, Edge, Firefox or Bitwarden CSV export.")
    parser.add_argument("file", help="path to the CSV file")
    parser.add_argument("--on-conflict", choices=("skip", "rename", "overwrite"), default="skip",
                        help="what to do when a name already exists (default: skip)")
    args = parser.parse_args(argv)

    session, vault = unlock_vault()
    if vault is None:
        return 1
    print()
    import_csv(vault, session, Path(args.file), on_conflict=args.on_conflict)
    print()
    return 0


def cmd_export(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="vault export", description="Create an encrypted export of the vault.")
    parser.add_argument("file", nargs="?", help="output path (optional)")
    args = parser.parse_args(argv)

    session, vault = unlock_vault()
    if vault is None:
        return 1
    print()
    if args.file:
        path = Path(args.file)
        secure_write(path, EXPORT_MAGIC + pack_container(session, vault))
        ok(f"Encrypted export written to '{path}'.")
    else:
        export_vault(session, vault)
    print()
    return 0


SUBCOMMANDS = {
    "get": cmd_get, "list": cmd_list, "gen": cmd_gen, "edit": cmd_edit, "delete": cmd_delete,
    "restore": cmd_restore, "run": cmd_run,
    "import": cmd_import, "export": cmd_export, "config": cmd_config,
    "doctor": cmd_doctor, "completion": cmd_completion,
}

HELP_COMMANDS = """\
commands:
  vault NAME                  find NAME (typos are OK) and copy its secret
  vault get NAME              same, for an entry whose name matches a command
  vault edit [NAME]           change one field of an entry
  vault delete NAME [--yes]   move an entry to encrypted trash
  vault restore [NAME]        bring back a deleted entry (kept for 30 days)
  vault run NAME... -- CMD    run CMD with those secrets as environment variables
  vault import FILE.csv       import logins from a browser / Bitwarden CSV
  vault export [FILE]         create an encrypted export
  vault gen                   generate a password or passphrase (no unlock needed)
  vault list [--json]         list saved names without secrets
  vault config                change timeouts and settings
  vault doctor [--deep|--json] check your setup
  vault completion ...        optional PowerShell tab-completion for entry names
"""


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--clear-clipboard":
        clipboard_cleaner_main()
        return 0

    split = argv.index("--") if "--" in argv else len(argv)
    head = [a for a in argv[:split] if a != "--no-color"]
    no_color = len(head) != split
    argv = head + argv[split:]
    apply_theme(effective_theme(no_color=no_color))

    try:
        if argv and argv[0] in SUBCOMMANDS:
            return SUBCOMMANDS[argv[0]](argv[1:])
        return legacy_main(argv, no_color)
    except (KeyboardInterrupt, EOFError):
        print()
        note("Vault closed.")
        return 0


def legacy_main(argv: List[str], no_color: bool) -> int:
    parser = argparse.ArgumentParser(
        prog="vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Secure Password Vault. Run with no arguments for the full menu.",
        epilog=HELP_COMMANDS + "\nexamples:  vault openai  |  vault tavily --show  |  vault --list  |  vault --theme light",
    )
    parser.add_argument("query", nargs="*", help="name (or part of it) to look up and copy")
    parser.add_argument("-s", "--show", action="store_true",
                        help=f"show the secret for {SHOW_SECONDS}s instead of copying it")
    parser.add_argument("-l", "--list", action="store_true", help="list saved names (no secrets)")
    parser.add_argument("--theme", choices=THEME_NAMES,
                        help="set and save the colour theme (dark, light, contrast, mono)")
    parser.add_argument("--no-color", action="store_true",
                        help="plain output with no colours (also: NO_COLOR environment variable)")
    parser.add_argument("--version", action="version", version=f"vault {VERSION}")
    args = parser.parse_args(argv)

    if args.show and not args.query:
        parser.error("--show needs a name to look up, e.g.: vault openai --show")

    if args.theme:
        save_config(theme=args.theme)
        apply_theme(effective_theme(no_color=no_color, requested=args.theme))
        print()
        ok(f"Theme set to '{args.theme}'. Preview:")
        print(f"    {HEAD}heading{RST}   {OK}{G_OK} success{RST}   {ERR}{G_ERR} error{RST}   "
              f"{WARN}{G_WARN} warning{RST}   {DIM}secondary{RST}   {INV} secret {RST}\n")
        return 0

    if args.query or args.list:
        return run_quick_lookup(args.query, show=args.show, list_only=args.list)
    return run_vault_app()


if __name__ == "__main__":
    sys.exit(main())