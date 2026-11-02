# -*- coding: utf-8 -*-
"""Two-factor authentication (TOTP) code generator (RFC 6238) (Improvement #9)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import sys
import time
from typing import Tuple


def clean_base32_secret(secret: str) -> bytes:
    """Normalize and pad base32 secret string."""
    clean = secret.replace(" ", "").replace("-", "").upper()
    missing_padding = len(clean) % 8
    if missing_padding:
        clean += "=" * (8 - missing_padding)
    return base64.b32decode(clean, casefold=True)


def generate_totp(
    secret: str,
    interval: int = 30,
    digits: int = 6,
    for_time: float | None = None,
) -> Tuple[str, int]:
    """Generate TOTP token and remaining validity seconds."""
    key = clean_base32_secret(secret)
    current_time = int(for_time if for_time is not None else time.time())
    counter = current_time // interval
    remaining = interval - (current_time % interval)

    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return f"{code_int:0{digits}d}", remaining


def display_totp_live(secret: str, label: str = "") -> None:
    """Display real-time updating TOTP code with animated countdown."""
    try:
        clean_base32_secret(secret)
    except Exception as e:
        print(f"Invalid TOTP secret: {e}")
        return

    print(f"\n  TOTP Authenticator: {label}")
    print("  (Press Ctrl+C to exit)\n")

    try:
        while True:
            code, remaining = generate_totp(secret)
            bar_len = 15
            filled = int((remaining / 30.0) * bar_len)
            bar = "■" * filled + "·" * (bar_len - filled)
            formatted = f"{code[:3]} {code[3:]}" if len(code) == 6 else code

            if sys.stdout.isatty():
                sys.stdout.write(f"\r   Code: \033[1;96m{formatted}\033[0m   [{bar}] {remaining:2d}s remaining ")
                sys.stdout.flush()
            else:
                print(f"Code: {formatted} ({remaining}s remaining)")
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n")

