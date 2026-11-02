# -*- coding: utf-8 -*-
"""Constants and environment definitions for Secure Password Vault."""
from __future__ import annotations

import os
import re
from pathlib import Path

VERSION = "3.4.0"
CREATOR_NAME = "Shashank"

DEFAULT_CLIPBOARD_TIMEOUT = 15
DEFAULT_SHOW_SECONDS = 10
DEFAULT_AUTO_LOCK_SECONDS = 300

MAX_LOGIN_ATTEMPTS = 3
EXPIRY_WARN_DAYS = 30
ROTATE_AFTER_DAYS = 180
TRASH_DAYS = 30
BACKUP_STALE_DAYS = 30
FUZZY_CUTOFF = 0.55

# Cryptographic parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4

SCRYPT_N_LOG2 = 17
SCRYPT_R = 8
SCRYPT_P = 1
LEGACY_PBKDF2_ITERATIONS = 480_000

# Container Magic headers
VAULT_MAGIC_V3 = b"PVLT3"  # Argon2id + AES-256-GCM AEAD
VAULT_MAGIC_V2 = b"PVLT2"  # Scrypt + Fernet
VAULT_MAGIC = VAULT_MAGIC_V3
OLD_BACKUP_MAGIC = b"PVBK1"
TRASH_MAGIC = b"PVTR1"
TRASH_MAGIC_V3 = b"PVTR3"
EXPORT_MAGIC = b"PVEX1"
EXPORT_MAGIC_V3 = b"PVEX3"

VAULT_SCHEMA_VERSION = 2

# Paths
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
SNAPSHOTS_DIR = APP_DIR / "snapshots"
QUICK_UNLOCK_FILE = APP_DIR / "quick_unlock.dat"

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

