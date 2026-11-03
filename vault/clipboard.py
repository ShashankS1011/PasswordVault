# -*- coding: utf-8 -*-
"""Clipboard operations with Windows Clipboard History suppression and auto-clearing."""
from __future__ import annotations

import atexit
import ctypes
import hashlib
import hmac
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import pyperclip

    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False

_last_copied_digest: Optional[str] = None
_CLIPBOARD_EPHEMERAL_KEY: bytes = os.urandom(32)


def _compute_clipboard_token(content: str, key: Optional[bytes] = None) -> str:
    """Compute keyed HMAC verification token for clipboard zeroing comparison."""
    active_key = key if key is not None else _CLIPBOARD_EPHEMERAL_KEY
    return hmac.new(active_key, content.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Windows Secure Clipboard Integration (Improvement #1)
# ---------------------------------------------------------------------------
def _windows_set_clipboard_safe(text: str) -> bool:
    """Copy text on Windows while explicitly suppressing Clipboard History and Cloud Sync."""
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]

        GMEM_MOVEABLE = 0x0002
        GMEM_ZEROINIT = 0x0040

        if not user32.OpenClipboard(None):
            return False
        try:
            user32.EmptyClipboard()
            # 1. CF_UNICODETEXT (13)
            encoded = text.encode("utf-16le") + b"\x00\x00"
            h_text = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if h_text:
                p_text = kernel32.GlobalLock(h_text)
                ctypes.memmove(p_text, encoded, len(encoded))
                kernel32.GlobalUnlock(h_text)
                user32.SetClipboardData(13, h_text)

            # 2. Suppress Windows 10/11 Clipboard History (Win+V) & Cloud Clipboard
            for fmt_name in (
                "CanIncludeInClipboardHistory",
                "CanUploadToCloudStore",
                "ExcludeClipboardContentFromMonitorProcessing",
            ):
                cf = user32.RegisterClipboardFormatW(fmt_name)
                if cf:
                    h_flag = kernel32.GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
                    if h_flag:
                        user32.SetClipboardData(cf, h_flag)
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def _clipboard_copy(text: str) -> bool:
    """Try Windows secure clipboard first, then pyperclip, then OS fallbacks."""
    if os.name == "nt":
        if _windows_set_clipboard_safe(text):
            return True

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
    elif sys.platform == "darwin":
        try:
            proc = subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
            return proc.returncode == 0
        except Exception:
            pass
    elif os.name == "posix":
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"]):
            try:
                proc = subprocess.run(cmd, input=text.encode("utf-8"), check=True)
                if proc.returncode == 0:
                    return True
            except Exception:
                continue

    return False


def _clipboard_paste() -> str:
    """Retrieve current clipboard string."""
    if HAS_PYPERCLIP:
        try:
            return pyperclip.paste()
        except Exception:
            pass
    return ""


def clear_clipboard_if_ours() -> None:
    """Clear clipboard only if it still matches the digest of the secret we copied."""
    global _last_copied_digest
    try:
        if _last_copied_digest:
            current = _clipboard_paste()
            if current and _compute_clipboard_token(current) == _last_copied_digest:
                _clipboard_copy("")
            _last_copied_digest = None
    except Exception:
        pass


atexit.register(clear_clipboard_if_ours)


# ---------------------------------------------------------------------------
# Background Clipboard Cleaner Subprocess
# ---------------------------------------------------------------------------
def clipboard_cleaner_main() -> None:
    """Standalone process entrypoint invoked with --clear-clipboard."""
    key_hex = sys.stdin.readline().strip()
    expected_token = sys.stdin.readline().strip()
    delay = float(sys.stdin.readline().strip())
    time.sleep(delay)
    try:
        current = _clipboard_paste()
        key = bytes.fromhex(key_hex)
        if _compute_clipboard_token(current, key=key) == expected_token:
            _clipboard_copy("")
    except Exception:
        pass


def spawn_clipboard_cleaner(text: str, timeout: int) -> bool:
    """Spawn an independent background cleaner process that outlives the terminal."""
    try:
        frozen = getattr(sys, "frozen", False)
        cmd = [sys.executable, "--clear-clipboard"]
        if not frozen:
            script_path = str(Path(__file__).resolve().parents[1] / "vault.py")
            cmd = [sys.executable, script_path, "--clear-clipboard"]

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
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **kwargs)
        token = _compute_clipboard_token(text)
        if proc.stdin:
            proc.stdin.write(f"{_CLIPBOARD_EPHEMERAL_KEY.hex()}\n{token}\n{timeout}\n".encode("utf-8"))
            proc.stdin.close()
        return True
    except Exception:
        return False


def render_countdown_bar(remaining: int, total: int, width: int = 15) -> str:
    """Render a clean ASCII progress bar for clipboard clearing countdown."""
    frac = max(0.0, min(1.0, remaining / max(1, total)))
    filled = int(round(frac * width))
    empty = width - filled
    return f"[{'=' * filled}{'.' * empty}]"


def copy_with_autoclear(
    text: str,
    timeout: int = 15,
    block_if_needed: bool = False,
    ui_callbacks: Optional[Dict[str, Any]] = None,
) -> None:
    """Copy secret to clipboard and schedule automated zeroing."""
    global _last_copied_digest
    digest = _compute_clipboard_token(text)

    if not _clipboard_copy(text):
        if ui_callbacks and "err" in ui_callbacks:
            ui_callbacks["err"]("Clipboard is not available.")
            ui_callbacks["note"]("Install pyperclip (`pip install pyperclip`) or use --show.")
            sys.stdout.write(f"\n  Value (copy manually):\n  {text}\n\n")
            sys.stdout.flush()
        return

    _last_copied_digest = digest
    helper_started = spawn_clipboard_cleaner(text, timeout)

    if ui_callbacks and "ok" in ui_callbacks:
        print()
        ui_callbacks["ok"](f"Copied to clipboard  ·  auto-clears in {timeout}s")

    if helper_started and not block_if_needed:
        return

    if block_if_needed:
        try:
            for remaining in range(timeout, 0, -1):
                if sys.stdout.isatty():
                    bar = render_countdown_bar(remaining, timeout)
                    print(f"\r  Clipboard auto-clears in {bar} {remaining:2d}s (Ctrl+C to clear now)  ", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        clear_clipboard_if_ours()
        if sys.stdout.isatty():
            print("\r" + " " * 75, end="\r")
        if ui_callbacks and "ok" in ui_callbacks:
            ui_callbacks["ok"]("Clipboard cleared.")
    else:
        def background_clear() -> None:
            time.sleep(timeout)
            clear_clipboard_if_ours()

        threading.Thread(target=background_clear, daemon=True).start()

