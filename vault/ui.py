# -*- coding: utf-8 -*-
"""Terminal UI formatting, themes, ASCII QR rendering, and non-blocking AutoLock."""
from __future__ import annotations

import ctypes
import getpass
import math
import os
import shutil
import string
import sys
import threading
import time
import webbrowser
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
G_ML, G_MR = "├", "┤"
G_CROSS = "┼"

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
    "dracula": {
        "HEAD": "\033[38;5;141m",
        "OK": "\033[38;5;84m",
        "ERR": "\033[38;5;210m",
        "WARN": "\033[38;5;228m",
        "DIM": "\033[38;5;103m",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[38;5;212m",
        "MUTED": "\033[38;5;103m",
        "BOX": "\033[38;5;141m",
    },
    "nord": {
        "HEAD": "\033[38;5;110m",
        "OK": "\033[38;5;150m",
        "ERR": "\033[38;5;203m",
        "WARN": "\033[38;5;179m",
        "DIM": "\033[38;5;244m",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[38;5;111m",
        "MUTED": "\033[38;5;244m",
        "BOX": "\033[38;5;110m",
    },
    "solarized-dark": {
        "HEAD": "\033[38;5;37m",
        "OK": "\033[38;5;64m",
        "ERR": "\033[38;5;160m",
        "WARN": "\033[38;5;136m",
        "DIM": "\033[38;5;240m",
        "BOLD": "\033[1m",
        "INV": "\033[7m",
        "RST": "\033[0m",
        "ACCENT": "\033[38;5;33m",
        "MUTED": "\033[38;5;241m",
        "BOX": "\033[38;5;37m",
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


def confirm_action(prompt_text: str, default: bool = False, danger: bool = False) -> bool:
    """Safety-first confirmation dialog with highlighted defaults and danger warnings."""
    if default:
        hint = f"[{BOLD}{OK}Y{RST}/{ERR}n{RST}]"
    else:
        hint = f"[{OK}y{RST}/{BOLD}{ERR}N{RST}]"
    icon = f"{ERR}{G_WARN}{RST}" if danger else f"{WARN}?{RST}"
    try:
        ans = input(f"  {icon} {prompt_text} {hint}: ").strip().lower()
        if not ans:
            return default
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


def calculate_entropy(password: str) -> Tuple[float, str]:
    """Calculate Shannon entropy bits and estimate brute-force crack time."""
    if not password:
        return 0.0, "< 1 second"

    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c.isspace() for c in password):
        pool += 1
    syms = sum(1 for c in password if not c.isalnum() and not c.isspace())
    if syms > 0:
        pool += 33

    pool = max(pool, 2)
    entropy = len(password) * math.log2(pool)

    # Assume 10 billion guesses/second
    log2_seconds = entropy - 33.21928094887362

    if log2_seconds < 0:
        crack_time = "< 1 second"
    else:
        seconds = 2.0 ** min(log2_seconds, 128.0)
        if seconds < 60:
            crack_time = f"{max(1, int(seconds))} seconds"
        elif seconds < 3600:
            crack_time = f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            crack_time = f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            crack_time = f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 1000:
            crack_time = f"{int(seconds // 31536000)} years"
        else:
            crack_time = "centuries"

    return round(entropy, 1), crack_time


def character_breakdown(password: str) -> str:
    """Format character composition breakdown badges."""
    length = len(password)
    upper = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    digits = sum(1 for c in password if c.isdigit())
    syms = sum(1 for c in password if not c.isalnum() and not c.isspace())
    return (
        f"{MUTED}[len: {length}] "
        f"[upper: {upper}] "
        f"[lower: {lower}] "
        f"[digit: {digits}] "
        f"[sym: {syms}]{RST}"
    )


def mask_secret(secret: str, revealed: bool = False, mask_char: str = "•") -> str:
    """Mask or reveal sensitive secret strings."""
    if revealed:
        return secret
    return mask_char * len(secret)


def render_health_gauge(score: int, width: int = 20) -> str:
    """Render a visual health meter gauge (0-100%)."""
    score = max(0, min(100, score))
    filled = int(round((score / 100.0) * width))
    empty = width - filled
    if score >= 80:
        color = OK
        label = "Excellent" if score >= 90 else "Good"
    elif score >= 50:
        color = WARN
        label = "Fair"
    else:
        color = ERR
        label = "Action Needed"

    bar = f"{color}{G_BAR_ON * filled}{MUTED}{G_BAR_OFF * empty}{RST}"
    return f"{bar} {BOLD}{color}{score}%{RST} {MUTED}({label}){RST}"


def highlight_matches(text: str, query: str) -> str:
    """Highlight matched search characters or substring with color."""
    if not query:
        return text
    idx = text.lower().find(query.lower())
    if idx == -1:
        return text
    start = idx
    end = idx + len(query)
    return (
        text[:start]
        + f"{BOLD}{ACCENT}{text[start:end]}{RST}"
        + highlight_matches(text[end:], query)
    )


def open_url(url: str) -> bool:
    """Open URL in the host's default web browser."""
    if not url:
        return False
    target = url.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target
    try:
        return webbrowser.open(target)
    except Exception:
        return False


def render_diff(old_entry: Dict[str, Any], new_entry: Dict[str, Any]) -> None:
    """Side-by-side / columnar visual diff showing changed fields between revisions."""
    all_keys = sorted(set(old_entry.keys()) | set(new_entry.keys()))
    changes: List[Tuple[str, str, str]] = []
    for k in all_keys:
        if k in ("history", "attachments"):
            continue
        v_old = old_entry.get(k)
        v_new = new_entry.get(k)
        if v_old != v_new:
            is_secret = "password" in k or "api_key" in k or "totp" in k
            s_old = mask_secret(str(v_old)) if is_secret and v_old else str(v_old if v_old is not None and v_old != "" else G_EMPTY)
            s_new = mask_secret(str(v_new)) if is_secret and v_new else str(v_new if v_new is not None and v_new != "" else G_EMPTY)
            changes.append((k, s_old, s_new))

    if not changes:
        note("No field modifications detected.")
        return

    print(f"\n  {HEAD}{BOLD}Modifications Summary:{RST}")
    for field, old_val, new_val in changes:
        print(f"    {BOLD}{field:<14}:{RST} {ERR}- {old_val}{RST}")
        print(f"    {' ' * 14}  {OK}+ {new_val}{RST}")
    print()


def render_credential_card(
    name: str,
    entry: Dict[str, Any],
    show_secret: bool = False,
) -> None:
    """Render structured card with aligned borders and highlighted fields."""
    from vault.features.totp import generate_totp
    from vault.models import entry_custom_fields, entry_secret, entry_totp, entry_type

    width = min(term_width() - 4, 76)
    content_w = width - 4

    etype = entry_type(entry)
    secret_val = entry_secret(entry)
    masked_val = secret_val if show_secret else mask_secret(secret_val)

    print()
    print(f"  {BOX}{G_TL}{G_H * (width - 2)}{G_TR}{RST}")
    hdr_left = f"{BOLD}{name}{RST}"
    hdr_right = f"{MUTED}[type: {HEAD}{etype}{MUTED}]{RST}"
    pad = content_w - (len(name) + len(f"[type: {etype}]"))
    pad_str = " " * max(1, pad)
    print(f"  {BOX}{G_V}{RST} {hdr_left}{pad_str}{hdr_right} {BOX}{G_V}{RST}")
    print(f"  {BOX}{G_ML}{G_H * (width - 2)}{G_MR}{RST}")

    rows: List[Tuple[str, str, int]] = []
    if entry.get("username"):
        rows.append(("Username", f"{BOLD}{entry['username']}{RST}", len(str(entry["username"]))))
    if secret_val:
        label = "API Key" if etype == "api_key" else "Password"
        rows.append((label, f"{ACCENT}{masked_val}{RST}", len(masked_val)))
    if entry.get("url"):
        rows.append(("URL", f"{HEAD}{entry['url']}{RST}", len(str(entry["url"]))))
    totp_seed = entry_totp(entry)
    if totp_seed:
        code, rem = generate_totp(totp_seed)
        totp_txt = f"{OK}{code[:3]} {code[3:]}{RST} {MUTED}({rem}s left){RST}"
        rows.append(("TOTP (2FA)", totp_txt, len(f"{code[:3]} {code[3:]} ({rem}s left)")))
    if entry.get("tags"):
        tag_str = ", ".join(entry["tags"])
        rows.append(("Tags", f"{MUTED}{tag_str}{RST}", len(tag_str)))
    if entry.get("created"):
        rows.append(("Created", str(entry["created"]), len(str(entry["created"]))))
    if entry.get("expires"):
        rows.append(("Expires", f"{WARN}{entry['expires']}{RST}", len(str(entry["expires"]))))
    if entry.get("notes"):
        notes_str = str(entry["notes"])
        if len(notes_str) > content_w - 16:
            notes_str = notes_str[: content_w - 19] + "..."
        rows.append(("Notes", notes_str, len(notes_str)))

    for k, v in entry_custom_fields(entry).items():
        v_str = str(v)
        rows.append((k, v_str, len(v_str)))

    for label, val_styled, raw_len in rows:
        label_col = f"{MUTED}{label:<12}:{RST}"
        avail = content_w - 14
        extra = max(0, avail - raw_len)
        print(f"  {BOX}{G_V}{RST} {label_col} {val_styled}{' ' * extra} {BOX}{G_V}{RST}")

    print(f"  {BOX}{G_BL}{G_H * (width - 2)}{G_BR}{RST}")
    print()


def render_breadcrumbs(*steps: str) -> None:
    """Render hierarchical breadcrumb trail navigation."""
    if not steps:
        return
    parts = []
    for i, step in enumerate(steps):
        if i == len(steps) - 1:
            parts.append(f"{BOLD}{HEAD}{step}{RST}")
        else:
            parts.append(f"{MUTED}{step}{RST}")
    sep = f" {MUTED}{G_PROMPT}{RST} "
    print(f"\n  {sep.join(parts)}\n")


def render_footer_shortcuts(shortcuts: List[Tuple[str, str]]) -> None:
    """Render contextual keyboard shortcut legend footer bar."""
    if not shortcuts:
        return
    rendered = [f"{HEAD}[{k}]{RST} {MUTED}{desc}{RST}" for k, desc in shortcuts]
    print(f"  {'  '.join(rendered)}")


def prompt_tags(existing_tags: List[str], current: Optional[List[str]] = None) -> List[str]:
    """Interactive tag selector with suggestions from existing tags."""
    cur = current or []
    if existing_tags:
        unique = sorted(set(existing_tags))
        note(f"Known tags: {', '.join(unique)}")
    cur_str = ", ".join(cur) if cur else ""
    val = prompt(f"Tags [{cur_str}]: ").strip()
    if not val:
        return cur
    return [t.strip() for t in val.split(",") if t.strip()]


def paginate_list(items: List[str], page_size: int = 10, title: str = "Entries") -> Optional[str]:
    """Display paginated list for large vaults with navigation."""
    if not items:
        note("No items to display.")
        return None
    if len(items) <= page_size or not sys.stdin.isatty():
        for idx, item in enumerate(items, 1):
            print(f"    {HEAD}{idx:>2}{RST}  {item}")
        return None

    total_pages = (len(items) + page_size - 1) // page_size
    page = 0
    while True:
        start_idx = page * page_size
        page_items = items[start_idx : start_idx + page_size]
        print(f"\n  {HEAD}{title}{RST} {MUTED}(Page {page + 1}/{total_pages}){RST}")
        for offset, item in enumerate(page_items, 1):
            print(f"    {HEAD}{start_idx + offset:>3}{RST}  {item}")

        nav = input(f"\n  {MUTED}[n]ext, [p]rev, [1-{len(items)}] select, [q]uit:{RST} ").strip().lower()
        if nav == "q":
            return None
        elif nav == "n":
            if page < total_pages - 1:
                page += 1
            else:
                note("Already at last page.")
        elif nav == "p":
            if page > 0:
                page -= 1
            else:
                note("Already at first page.")
        elif nav.isdigit():
            val = int(nav)
            if 1 <= val <= len(items):
                return items[val - 1]


def interactive_select(items: List[str], prompt_text: str = "Select entry") -> Optional[str]:
    """Interactive selection with live search and arrow key navigation."""
    if not items:
        return None
    if len(items) == 1:
        return items[0]

    # Non-TTY or fallback
    if not sys.stdin.isatty() or os.name != "nt":
        for idx, item in enumerate(items[:15], 1):
            print(f"    {HEAD}{idx:>2}{RST}  {item}")
        sel = prompt(f"{prompt_text} (1-{min(len(items), 15)}): ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(items):
            return items[int(sel) - 1]
        return items[0] if not sel else None

    try:
        import msvcrt

        query = ""
        selected_idx = 0
        max_visible = 8

        while True:
            filtered = [it for it in items if query.lower() in it.lower()] if query else list(items)
            if selected_idx >= len(filtered):
                selected_idx = max(0, len(filtered) - 1)

            print(f"\r  {ACCENT}{G_PROMPT}{RST} {prompt_text}: [{query}]" + " " * 20)
            start = max(0, selected_idx - max_visible // 2)
            visible = filtered[start : start + max_visible]

            for i, it in enumerate(visible):
                actual_idx = start + i
                is_sel = actual_idx == selected_idx
                prefix = f"  {ACCENT}>{RST} " if is_sel else "    "
                line = highlight_matches(it, query) if query else it
                styled = f"{INV}{line}{RST}" if is_sel else line
                print(f"\r{prefix}{styled}" + " " * 30)

            if not filtered:
                print(f"\r    {MUTED}(No matches){RST}" + " " * 30)

            print(f"\r  {MUTED}[Up/Down] Navigate  [Enter] Select  [Esc] Cancel  [Type] Filter{RST}", end="", flush=True)

            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                if code == "H":  # Up
                    if selected_idx > 0:
                        selected_idx -= 1
                elif code == "P":  # Down
                    if selected_idx < len(filtered) - 1:
                        selected_idx += 1
            elif ch in ("\r", "\n"):
                print()
                return filtered[selected_idx] if filtered else None
            elif ch == "\x1b":  # Escape
                print()
                return None
            elif ch in ("\b", "\x08"):
                if query:
                    query = query[:-1]
                    selected_idx = 0
            elif ord(ch) >= 32:
                query += ch
                selected_idx = 0
    except Exception:
        # Fallback to standard input
        for idx, item in enumerate(items[:15], 1):
            print(f"    {HEAD}{idx:>2}{RST}  {item}")
        sel = prompt(f"{prompt_text} (1-{min(len(items), 15)}): ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(items):
            return items[int(sel) - 1]
        return items[0]


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


def prompt_with_timeout(
    msg: str,
    timeout_seconds: int = 60,
    default: str = "",
) -> str:
    """Prompt the user for input with a countdown/timeout fallback.

    Returns entered string, or default if timeout expires.
    """
    if timeout_seconds <= 0:
        return default

    if not sys.stdin.isatty():
        try:
            val = input(f"  {ACCENT}{G_PROMPT}{RST} {msg} ")
            return val if val else default
        except (EOFError, KeyboardInterrupt, OSError):
            return default

    prompt_str = f"  {ACCENT}{G_PROMPT}{RST} {msg} "
    val, timed_out = timed_input(prompt_str, float(timeout_seconds))
    if timed_out or not val:
        return default
    return val



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
