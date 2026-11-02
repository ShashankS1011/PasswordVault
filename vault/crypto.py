# -*- coding: utf-8 -*-
"""Cryptographic operations, key derivation functions, and container formats."""
from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import struct
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    EXPORT_MAGIC,
    EXPORT_MAGIC_V3,
    LEGACY_PBKDF2_ITERATIONS,
    OLD_BACKUP_MAGIC,
    QUICK_UNLOCK_FILE,
    SALT_FILE,
    SCRYPT_N_LOG2,
    SCRYPT_P,
    SCRYPT_R,
    VAULT_FILE,
    VAULT_MAGIC_V2,
    VAULT_MAGIC_V3,
    VAULT_SCHEMA_VERSION,
)


def zero_buffer(buf: Any) -> None:
    """Best-effort zeroing of sensitive memory buffer."""
    if isinstance(buf, (bytearray, memoryview)):
        try:
            ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.byref(ptr), 0, len(buf))
        except Exception:
            for i in range(len(buf)):
                buf[i] = 0


def lock_memory(data: bytes | bytearray) -> bool:
    """Request OS to keep memory page resident (prevent swapping to disk)."""
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            addr = ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p).value
            if addr:
                return bool(kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(len(data))))
        except Exception:
            pass
    elif hasattr(ctypes, "CDLL"):
        try:
            libc = ctypes.CDLL(None)
            if hasattr(libc, "mlock"):
                addr = ctypes.cast(ctypes.c_char_p(bytes(data)), ctypes.c_void_p).value
                if addr:
                    return libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(data))) == 0
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Key Derivation
# ---------------------------------------------------------------------------
def derive_argon2_key(
    master_password: str,
    salt: bytes,
    iterations: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    lanes: int = ARGON2_PARALLELISM,
) -> bytes:
    """Derive a 32-byte raw key using Argon2id (RFC 9106)."""
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    raw = kdf.derive(master_password.encode("utf-8"))
    lock_memory(raw)
    return raw


def derive_scrypt_key(
    master_password: str,
    salt: bytes,
    n_log2: int = SCRYPT_N_LOG2,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """Derive urlsafe base64 key for Fernet using Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def derive_legacy_key(master_password: str, salt: bytes) -> bytes:
    """Derive urlsafe base64 key using legacy PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class Session:
    """Holds active cryptographic session parameters in memory."""

    def __init__(
        self,
        key: bytes,
        salt: bytes,
        n_log2: int = SCRYPT_N_LOG2,
        r: int = SCRYPT_R,
        p: int = SCRYPT_P,
        kdf_type: str = "argon2",
        raw_key: Optional[bytes] = None,
        argon2_time: int = ARGON2_TIME_COST,
        argon2_mem: int = ARGON2_MEMORY_COST,
        argon2_lanes: int = ARGON2_PARALLELISM,
    ) -> None:
        self.key = key  # urlsafe base64 key (for Fernet compatibility)
        self.salt = salt
        self.n_log2 = n_log2
        self.r = r
        self.p = p
        self.kdf_type = kdf_type
        self.argon2_time = argon2_time
        self.argon2_mem = argon2_mem
        self.argon2_lanes = argon2_lanes

        if raw_key is not None:
            self.raw_key = raw_key
        else:
            try:
                self.raw_key = base64.urlsafe_b64decode(key)
            except Exception:
                self.raw_key = key

        # Fernet compatibility instance
        try:
            self.fernet = Fernet(self.key)
        except Exception:
            self.fernet = Fernet(base64.urlsafe_b64encode(self.raw_key))

        # AES-GCM AEAD instance
        self.aesgcm = AESGCM(self.raw_key)

    def close(self) -> None:
        """Clear key material from memory."""
        if hasattr(self, "raw_key") and isinstance(self.raw_key, (bytearray, bytes)):
            try:
                zero_buffer(bytearray(self.raw_key))
            except Exception:
                pass


def new_session(master_password: str) -> Session:
    """Create a new session using Argon2id."""
    salt = os.urandom(16)
    raw_key = derive_argon2_key(
        master_password,
        salt,
        iterations=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        lanes=ARGON2_PARALLELISM,
    )
    b64_key = base64.urlsafe_b64encode(raw_key)
    return Session(
        key=b64_key,
        salt=salt,
        kdf_type="argon2",
        raw_key=raw_key,
        argon2_time=ARGON2_TIME_COST,
        argon2_mem=ARGON2_MEMORY_COST,
        argon2_lanes=ARGON2_PARALLELISM,
    )


def verify_master_password(session: Session, master_password: str) -> bool:
    """Verify master password against active session key without timing leaks."""
    if session.kdf_type == "argon2":
        check = derive_argon2_key(
            master_password,
            session.salt,
            session.argon2_time,
            session.argon2_mem,
            session.argon2_lanes,
        )
        return secrets.compare_digest(check, session.raw_key)
    else:
        check_b64 = derive_scrypt_key(master_password, session.salt, session.n_log2, session.r, session.p)
        return secrets.compare_digest(check_b64, session.key)


# ---------------------------------------------------------------------------
# Container Packing & Decryption (v3 AES-256-GCM + v2 Scrypt/Fernet)
# ---------------------------------------------------------------------------
_HEADER_LEN_V2 = len(VAULT_MAGIC_V2) + 16 + 3
_HEADER_LEN_V3 = len(VAULT_MAGIC_V3) + 16 + 1 + 2 + 1  # 5 + 16 + 4 = 25 bytes
_NONCE_LEN = 12


def pack_container(session: Session, vault_data: Dict[str, Any]) -> bytes:
    """Pack vault data into authenticated encrypted container (AEAD AES-256-GCM)."""
    from vault.models import validate_vault_data

    validate_vault_data(vault_data)
    payload = {
        "schema_version": VAULT_SCHEMA_VERSION,
        "entries": vault_data,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    if session.kdf_type == "argon2":
        # Format: MAGIC(5) + SALT(16) + TIME(1) + MEM_MB(2) + LANES(1)
        mem_mb = session.argon2_mem // 1024
        header = (
            VAULT_MAGIC_V3
            + session.salt
            + struct.pack("!BBH", session.argon2_time, session.argon2_lanes, mem_mb)
        )
        nonce = os.urandom(_NONCE_LEN)
        aad = header + nonce
        ciphertext = session.aesgcm.encrypt(nonce, payload_bytes, aad)
        return header + nonce + ciphertext
    else:
        # Fallback to v2 Scrypt + Fernet format
        token = session.fernet.encrypt(payload_bytes)
        header = VAULT_MAGIC_V2 + session.salt + bytes([session.n_log2, session.r, session.p])
        return header + token


def decrypt_container(data: bytes, master_password: str) -> Tuple[Session, Dict[str, Any]]:
    """Decrypt v3 (Argon2id + AES-GCM) or v2 (Scrypt + Fernet) vault container."""
    from vault.models import validate_vault_data

    if data.startswith(VAULT_MAGIC_V3):
        if len(data) <= _HEADER_LEN_V3 + _NONCE_LEN + 16:
            raise ValueError("vault container is corrupted or truncated")
        idx = len(VAULT_MAGIC_V3)
        salt = data[idx : idx + 16]
        idx += 16
        time_cost, lanes, mem_mb = struct.unpack("!BBH", data[idx : idx + 4])
        idx += 4
        mem_cost = mem_mb * 1024

        header = data[:_HEADER_LEN_V3]
        nonce = data[_HEADER_LEN_V3 : _HEADER_LEN_V3 + _NONCE_LEN]
        ciphertext = data[_HEADER_LEN_V3 + _NONCE_LEN :]
        aad = header + nonce

        raw_key = derive_argon2_key(
            master_password,
            salt,
            iterations=time_cost,
            memory_cost=mem_cost,
            lanes=lanes,
        )
        try:
            plaintext = AESGCM(raw_key).decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise InvalidToken("decryption failed or master password incorrect") from e

        payload = json.loads(plaintext.decode("utf-8"))
        vault = validate_vault_data(payload)
        session = Session(
            key=base64.urlsafe_b64encode(raw_key),
            salt=salt,
            kdf_type="argon2",
            raw_key=raw_key,
            argon2_time=time_cost,
            argon2_mem=mem_cost,
            argon2_lanes=lanes,
        )
        return session, vault

    elif data.startswith(VAULT_MAGIC_V2):
        if len(data) <= _HEADER_LEN_V2:
            raise ValueError("vault file too short")
        salt = data[len(VAULT_MAGIC_V2) : len(VAULT_MAGIC_V2) + 16]
        n_log2, r, p = data[len(VAULT_MAGIC_V2) + 16 : _HEADER_LEN_V2]
        if not (10 <= n_log2 <= 20 and 1 <= r <= 16 and 1 <= p <= 4):
            raise ValueError("unsupported encryption settings")
        key = derive_scrypt_key(master_password, salt, n_log2, r, p)
        try:
            payload = json.loads(Fernet(key).decrypt(data[_HEADER_LEN_V2:]).decode("utf-8"))
        except Exception as e:
            raise InvalidToken("decryption failed or master password incorrect") from e

        vault = validate_vault_data(payload)
        session = Session(
            key=key,
            salt=salt,
            n_log2=n_log2,
            r=r,
            p=p,
            kdf_type="scrypt",
            raw_key=base64.urlsafe_b64decode(key),
        )
        return session, vault

    else:
        raise ValueError("unrecognized vault format header")


def decrypt_legacy(token: bytes, master_password: str, salt: bytes) -> Dict[str, Any]:
    """Decrypt v1 legacy PBKDF2 container."""
    from vault.models import validate_vault_data

    key = derive_legacy_key(master_password, salt)
    return validate_vault_data(json.loads(Fernet(key).decrypt(token).decode("utf-8")))


def decrypt_any_backup(data: bytes, master_password: str) -> Dict[str, Any]:
    """Universal decryptor handling v3, v2, v1, and export archives."""
    if data.startswith(VAULT_MAGIC_V3) or data.startswith(VAULT_MAGIC_V2):
        return decrypt_container(data, master_password)[1]
    if data.startswith(EXPORT_MAGIC_V3):
        return decrypt_container(data[len(EXPORT_MAGIC_V3) :], master_password)[1]
    if data.startswith(EXPORT_MAGIC):
        return decrypt_container(data[len(EXPORT_MAGIC) :], master_password)[1]
    if data.startswith(OLD_BACKUP_MAGIC):
        start = len(OLD_BACKUP_MAGIC)
        return decrypt_legacy(data[start + 16 :], master_password, data[start : start + 16])
    for path in (SALT_FILE, SALT_FILE.with_suffix(".v1.bak")):
        if path.exists():
            salt = path.read_bytes()
            try:
                return decrypt_legacy(data, master_password, salt)
            except InvalidToken:
                continue
    raise InvalidToken()


def save_vault(session: Session, vault_data: Dict[str, Any]) -> None:
    """Save vault data securely with atomic write and snapshot backup."""
    from vault.storage import secure_write, sync_names_index, take_snapshot

    take_snapshot(VAULT_FILE)
    secure_write(VAULT_FILE, pack_container(session, vault_data))
    sync_names_index(vault_data)


def open_vault_file(master_password: str) -> Tuple[Optional[Session], Dict[str, Any], bool]:
    """Open and decrypt local vault file; reports if migration is required."""
    data = VAULT_FILE.read_bytes()
    if data.startswith(VAULT_MAGIC_V3):
        session, vault = decrypt_container(data, master_password)
        return session, vault, False
    elif data.startswith(VAULT_MAGIC_V2):
        session, vault = decrypt_container(data, master_password)
        return session, vault, True  # needs upgrade to v3 Argon2id
    elif SALT_FILE.exists():
        salt = SALT_FILE.read_bytes()
        return None, decrypt_legacy(data, master_password, salt), True
    raise ValueError("Unrecognized vault file format")


def migrate_to_argon2(master_password: str, vault: Dict[str, Any]) -> Session:
    """Upgrade existing vault to Argon2id + AEAD AES-256-GCM container."""
    from vault.storage import secure_write

    if VAULT_FILE.exists():
        backup_file = VAULT_FILE.with_suffix(".enc.pre-v3.bak")
        backup_file.write_bytes(VAULT_FILE.read_bytes())

    session = new_session(master_password)
    save_vault(session, vault)
    # Verify roundtrip
    _, check = decrypt_container(VAULT_FILE.read_bytes(), master_password)
    if check != vault:
        if VAULT_FILE.with_suffix(".enc.pre-v3.bak").exists():
            secure_write(VAULT_FILE, VAULT_FILE.with_suffix(".enc.pre-v3.bak").read_bytes())
        raise RuntimeError("upgrade verification failed; original vault left untouched")
    return session


# Backwards compatibility alias
migrate_to_scrypt = migrate_to_argon2


# ---------------------------------------------------------------------------
# Windows DPAPI Quick Unlock (Improvement #21)
# ---------------------------------------------------------------------------
def is_dpapi_available() -> bool:
    return os.name == "nt" and hasattr(ctypes, "windll")


def _dpapi_protect(data: bytes, entropy: bytes = b"") -> bytes:
    if not is_dpapi_available():
        raise NotImplementedError("DPAPI is only available on Windows")
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    blob_out = DATA_BLOB()
    blob_ent = (
        DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_byte)))
        if entropy
        else None
    )
    p_ent = ctypes.byref(blob_ent) if blob_ent else None

    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        "VaultQuickUnlock",
        p_ent,
        None,
        None,
        0x01,
        ctypes.byref(blob_out),
    ):
        raise RuntimeError("CryptProtectData failed")

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    kernel32.LocalFree(blob_out.pbData)
    return result


def _dpapi_unprotect(cipher: bytes, entropy: bytes = b"") -> bytes:
    if not is_dpapi_available():
        raise NotImplementedError("DPAPI is only available on Windows")
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    blob_in = DATA_BLOB(len(cipher), ctypes.cast(ctypes.create_string_buffer(cipher), ctypes.POINTER(ctypes.c_byte)))
    blob_out = DATA_BLOB()
    blob_ent = (
        DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_byte)))
        if entropy
        else None
    )
    p_ent = ctypes.byref(blob_ent) if blob_ent else None

    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        p_ent,
        None,
        None,
        0x01,
        ctypes.byref(blob_out),
    ):
        raise RuntimeError("CryptUnprotectData failed")

    result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    kernel32.LocalFree(blob_out.pbData)
    return result


def save_quick_unlock(session: Session, pin: str, timeout_seconds: int = 7200) -> bool:
    """Store DPAPI-protected session key with PIN entropy for quick unlock."""
    if not is_dpapi_available() or not pin:
        return False
    try:
        data = {
            "key": base64.b64encode(session.raw_key).decode("ascii"),
            "salt": base64.b64encode(session.salt).decode("ascii"),
            "kdf_type": session.kdf_type,
            "argon2_time": session.argon2_time,
            "argon2_mem": session.argon2_mem,
            "argon2_lanes": session.argon2_lanes,
            "expires_at": time.time() + timeout_seconds,
        }
        encoded = json.dumps(data).encode("utf-8")
        pin_entropy = hashes.Hash(hashes.SHA256())
        pin_entropy.update(pin.encode("utf-8"))
        entropy = pin_entropy.finalize()

        protected = _dpapi_protect(encoded, entropy)
        QUICK_UNLOCK_FILE.write_bytes(protected)
        return True
    except Exception:
        return False


def try_quick_unlock(pin: str) -> Optional[Session]:
    """Attempt quick unlock using DPAPI and user PIN."""
    if not is_dpapi_available() or not QUICK_UNLOCK_FILE.exists() or not pin:
        return None
    try:
        protected = QUICK_UNLOCK_FILE.read_bytes()
        pin_entropy = hashes.Hash(hashes.SHA256())
        pin_entropy.update(pin.encode("utf-8"))
        entropy = pin_entropy.finalize()

        unprotected = _dpapi_unprotect(protected, entropy)
        data = json.loads(unprotected.decode("utf-8"))
        if time.time() > data.get("expires_at", 0):
            QUICK_UNLOCK_FILE.unlink(missing_ok=True)
            return None

        raw_key = base64.b64decode(data["key"])
        salt = base64.b64decode(data["salt"])
        return Session(
            key=base64.urlsafe_b64encode(raw_key),
            salt=salt,
            kdf_type=data.get("kdf_type", "argon2"),
            raw_key=raw_key,
            argon2_time=data.get("argon2_time", ARGON2_TIME_COST),
            argon2_mem=data.get("argon2_mem", ARGON2_MEMORY_COST),
            argon2_lanes=data.get("argon2_lanes", ARGON2_PARALLELISM),
        )
    except Exception:
        return None


def clear_quick_unlock() -> None:
    """Purge any saved quick unlock credentials."""
    try:
        QUICK_UNLOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass
