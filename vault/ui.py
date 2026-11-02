# -*- coding: utf-8 -*-
"""Terminal UI formatting, themes, ASCII QR rendering, and non-blocking AutoLock."""
from __future__ import annotations

import ctypes
import getpass
import os
import shutil
import string
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from vault.constants import (
    DEFAULT_AUTO_LOCK_SECONDS,
)

# Glyphs
G_OK = "✓"
G_WARN = "!"
G_ERR = "×"
G_BULLET = "·"
G_DOT = "•"
G_PROMPT = "›"
G_BAR_ON = "■"
G_BAR_OFF = "·"
G_EMPTY = "—"
G_TL, G_TR, G_BL, G_BR = "┌", "┐", "└", "┘"
G_H, G_V = "─", "│"

# ---------------------------------------------------------------------------
# Theme System & Auto-Detection (Improvement #33)
# ---------------------------------------------------------------------------
THEMES: Dict[str, Dict[str, str]] = {
    "dark": {
        "HEAD": "\033[36m",
        "OK": "\033[32m",
        "ERR": "\033[31m",
        "WARN": "\033[33m",
        "DIM": "\033[2m",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[96m",
        "MUTED": "\033[90m",
        "BOX": "\033[36m",
    },
    "light": {
        "HEAD": "\033[34m",
        "OK": "\033[38;5;28m",
        "ERR": "\033[31m",
        "WARN": "\033[38;5;130m",
        "DIM": "\033[38;5;243m",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[38;5;25m",
        "MUTED": "\033[38;5;245m",
        "BOX": "\033[34m",
    },
    "contrast": {
        "HEAD": "\033[1;96m",
        "OK": "\033[1;92m",
        "ERR": "\033[1;91m",
        "WARN": "\033[1;93m",
        "DIM": "",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[1;96m",
        "MUTED": "\033[1;37m",
        "BOX": "\033[1;96m",
    },
    "mono": {k: "" for k in ("HEAD", "OK", "ERR", "WARN", "DIM", "BOLD", "INV", "RST", "ACCENT", "MUTED", "BOX")},
}

THEME_NAMES = list(THEMES)
HEAD = OK = ERR = WARN = DIM = BOLD = INV = RST = ACCENT = MUTED = BOX = ""
_vt_enabled = False


def detect_system_theme() -> str:
    """Detect whether host OS is using dark or light theme (Improvement #33)."""
    if os.name == "nt":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            )
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return "light" if value == 1 else "dark"
        except Exception:
            return "dark"
    elif sys.platform == "darwin":
        try:
            import subprocess

            res = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
            )
            return "dark" if "Dark" in res.stdout else "light"
        except Exception:
            return "dark"
    return "dark"


def apply_theme(name: str) -> None:
    global HEAD, OK, ERR, WARN, DIM, BOLD, INV, RST, ACCENT, MUTED, BOX, _vt_enabled
    theme_data = THEMES.get(name, THEMES["dark"])
    HEAD = theme_data["HEAD"]
    OK = theme_data["OK"]
    ERR = theme_data["ERR"]
    WARN = theme_data["WARN"]
    DIM = theme_data["DIM"]
    BOLD = theme_data["BOLD"]
    INV = theme_data["INV"]
    RST = theme_data["RST"]
    ACCENT = theme_data["ACCENT"]
    MUTED = theme_data["MUTED"]
    BOX = theme_data["BOX"]

    if name != "mono" and os.name == "nt" and not _vt_enabled:
        os.system("")
        _vt_enabled = True


def effective_theme(no_color: bool = False, requested: Optional[str] = None) -> str:
    if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return "mono"
    from vault.storage import load_config

    chosen = requested or load_config().get("theme", "auto")
    if chosen == "auto":
        chosen = detect_system_theme()
    return chosen if chosen in THEMES else "dark"


apply_theme("dark")


# ---------------------------------------------------------------------------
# Formatting Helpers
# ---------------------------------------------------------------------------
def term_width() -> int:
    return max(60, min(shutil.get_terminal_size((80, 24)).columns, 100))


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def wipe_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="", flush=True)


def ok(msg: str) -> None:
    print(f"  {OK}{G_OK}{RST} {msg}")


def err(msg: str) -> None:
    print(f"  {ERR}{G_ERR}{RST} {msg}")


def warn(msg: str) -> None:
    print(f"  {WARN}{G_WARN}{RST} {msg}")


def note(msg: str) -> None:
    print(f"  {MUTED}{msg}{RST}")


def prompt(msg: str) -> str:
    return input(f"  {ACCENT}{G_PROMPT}{RST} {msg}")


def secret_prompt(msg: str) -> str:
    if sys.stdout.isatty():
        return getpass.getpass(f"  {ACCENT}{G_PROMPT}{RST} {msg}")
    return input(f"  {ACCENT}{G_PROMPT}{RST} {msg}")


def pause(msg: str = "Press Enter to continue...") -> None:
    try:
        input(f"\n  {MUTED}{msg}{RST} ")
    except (EOFError, KeyboardInterrupt):
        print()


def confirm(msg: str) -> bool:
    try:
        ans = input(f"  {WARN}?{RST} {msg} [y/N]: ").strip().lower()
        return ans in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def print_banner() -> None:
    from vault.constants import CREATOR_NAME, VERSION

    w = term_width() - 4
    print()
    print(f"  {HEAD}{G_TL}{G_H * w}{G_TR}{RST}")
    title = f"SECURE PASSWORD VAULT  v{VERSION}"
    sub = f"Zero-trust, local-first encrypted storage  ·  by {CREATOR_NAME}"
    print(f"  {HEAD}{G_V}{RST}  {BOLD}{title:<{w - 2}}{RST}{HEAD}{G_V}{RST}")
    print(f"  {HEAD}{G_V}{RST}  {MUTED}{sub:<{w - 2}}{RST}{HEAD}{G_V}{RST}")
    print(f"  {HEAD}{G_BL}{G_H * w}{G_BR}{RST}")
    print()


def print_header(title: str) -> None:
    print()
    print(f"  {HEAD}{BOLD}{title}{RST}")
    print(f"  {MUTED}{G_H * min(len(title) + 4, term_width() - 4)}{RST}")
    print()


class Spinner:
    def __init__(self, message: str = "") -> None:
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def __enter__(self) -> "Spinner":
        if sys.stdout.isatty():
            self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self._stop.set()
        if sys.stdout.isatty():
            self._thread.join()
            print("\r" + " " * (len(self.message) + 10) + "\r", end="", flush=True)

    def _spin(self) -> None:
        glyphs = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not self._stop.is_set():
            print(f"\r  {ACCENT}{glyphs[idx % len(glyphs)]}{RST} {self.message}...", end="", flush=True)
            idx += 1
            time.sleep(0.08)


# ---------------------------------------------------------------------------
# Password Strength Assessment
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


# ---------------------------------------------------------------------------
# Terminal ASCII QR Code Rendering (Improvement #32)
# ---------------------------------------------------------------------------
def render_qr_ascii(data: str) -> None:
    """Render an ASCII/Unicode QR code in terminal for mobile transfer."""
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(data)
        qr.make(fit=True)
        matrix = qr.get_matrix()
        lines = []
        for row in matrix:
            line = "".join("██" if cell else "  " for cell in row)
            lines.append("  " + line)
        try:
            print("\n" + "\n".join(lines) + "\n")
        except UnicodeEncodeError:
            ascii_lines = ["  " + "".join("##" if cell else "  " for cell in row) for row in matrix]
            print("\n" + "\n".join(ascii_lines) + "\n")
    except Exception as e:
        note(f"(QR generation unavailable: {e})")


# ---------------------------------------------------------------------------
# Non-blocking Timed Input and AutoLock Watchdog (Improvements #7 & #8)
# ---------------------------------------------------------------------------
def is_workstation_locked() -> bool:
    """Check if Windows desktop is currently locked (Win+L) (Improvement #8)."""
    if os.name == "nt":
        try:
            user32 = ctypes.windll.user32
            h_desk = user32.OpenInputDesktop(0, False, 0x0001)
            if not h_desk:
                return True
            user32.CloseDesktop(h_desk)
            return False
        except Exception:
            return False
    return False


def timed_input(prompt_text: str, timeout: float) -> Tuple[str, bool]:
    """Read a line of input with real-time timeout and workstation lock check."""
    print(prompt_text, end="", flush=True)
    start_time = time.time()

    if os.name == "nt" and sys.stdin.isatty():
        import msvcrt

        buf: List[str] = []
        while True:
            if time.time() - start_time > timeout or is_workstation_locked():
                print()
                return "", True  # timed out

            if msvcrt.kbhit():
                ch = msvcrt.getwche()
                if ch in ("\r", "\n"):
                    print()
                    return "".join(buf), False
                elif ch == "\b":
                    if buf:
                        buf.pop()
                        # erase character on console
                        print(" \b", end="", flush=True)
                elif ord(ch) >= 32:
                    buf.append(ch)
            time.sleep(0.05)
    else:
        # Fallback for pipes or non-Windows
        try:
            return input(), False
        except (EOFError, KeyboardInterrupt):
            return "", False


class AutoLock:
    """Watches inactivity and workstation locks to trigger immediate wipe (Improvements #7, #8)."""

    def __init__(self, timeout: int = DEFAULT_AUTO_LOCK_SECONDS) -> None:
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
            if is_workstation_locked() and not self.locked:
                self.locked = True
                wipe_screen()
                continue

            armed_at = self._armed_at
            if armed_at and not self.locked and time.time() - armed_at > self.timeout:
                self.locked = True
                wipe_screen()
                print()
                warn(f"Vault locked after {max(1, int(self.timeout // 60))} min of inactivity.")
                print(f"  {MUTED}Press Enter, then enter your master password to continue.{RST}")
