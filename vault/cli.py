# -*- coding: utf-8 -*-
"""Command-line interface, interactive TUI, and dispatching routines."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vault.clipboard import (
    clear_clipboard_now,
    clipboard_cleaner_main,
    copy_with_autoclear,
)
from vault.constants import (
    APP_DIR,
    DEFAULT_AUTO_LOCK_SECONDS,
    DEFAULT_CLIPBOARD_TIMEOUT,
    DEFAULT_SHOW_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    ROTATE_AFTER_DAYS,
    TRASH_DAYS,
    VAULT_FILE,
    VAULT_SCHEMA_VERSION,
    VERSION,
)
from vault.crypto import (
    Session,
    benchmark_argon2,
    decrypt_container,
    is_dpapi_available,
    migrate_to_argon2,
    open_vault_file,
    save_quick_unlock,
    save_vault,
    try_quick_unlock,
)
from vault.exporters import (
    export_csv,
    export_dotenv,
    export_encrypted_json,
    export_vault,
    to_env_name,
)
from vault.features.emergency import generate_emergency_kit
from vault.features.generator import (
    generate_candidates,
    generate_passphrase,
    generate_random_password,
    generate_random_token,
    generate_with_profile,
)
from vault.features.health import (
    calculate_entropy_audit,
    calculate_health_score,
    calculate_health_score_breakdown,
    check_entry_rotation_needed,
    collect_health,
    collect_vault_stats,
    find_matches,
    find_matches_regex,
    find_similar_passwords,
)
from vault.features.pwned import audit_vault_breaches, check_password_breach
from vault.features.totp import display_totp_live
from vault.importers import (
    import_bitwarden_json,
    import_csv,
    import_encrypted_json,
    import_keepass_xml,
)
from vault.integrations import (
    get_completion_script,
    handle_git_credential,
    run_native_messaging_host,
)
from vault.models import (
    days_until_expiry,
    entry_is_favorite,
    entry_secret,
    entry_totp,
    hostname_of,
    validate_entry,
    validate_vault_schema_detailed,
)
from vault.storage import (
    check_lockout,
    clear_failures,
    empty_trash,
    file_lock,
    list_snapshots,
    load_config,
    load_trash,
    prune_backups,
    record_failure,
    restore_from_trash,
    restore_snapshot,
    save_config,
    save_trash,
    trash_add,
    verify_backup,
)
from vault.ui import (
    ACCENT,
    BOLD,
    ERR,
    G_DOT,
    G_H,
    G_PROMPT,
    HEAD,
    INV,
    MUTED,
    OK,
    RST,
    THEME_NAMES,
    WARN,
    AutoLock,
    Spinner,
    apply_theme,
    calculate_entropy,
    character_breakdown,
    clear_screen,
    confirm,
    confirm_action,
    effective_theme,
    err,
    interactive_select,
    note,
    ok,
    open_url,
    pause,
    print_banner,
    print_header,
    prompt,
    prompt_tags,
    render_breadcrumbs,
    render_credential_card,
    render_diff,
    render_footer_shortcuts,
    render_health_gauge,
    render_qr_ascii,
    secret_prompt,
    strength_line,
    term_width,
    timed_input,
    warn,
    wipe_screen,
)


def _load_timeouts() -> Tuple[int, int, int]:
    cfg = load_config()
    return (
        int(cfg.get("clipboard_timeout", DEFAULT_CLIPBOARD_TIMEOUT)),
        int(cfg.get("show_seconds", DEFAULT_SHOW_SECONDS)),
        int(cfg.get("auto_lock_seconds", DEFAULT_AUTO_LOCK_SECONDS)),
    )


CLIPBOARD_TIMEOUT, SHOW_SECONDS, AUTO_LOCK_SECONDS = _load_timeouts()


# ---------------------------------------------------------------------------
# Master Password Prompting & Authentication (Improvement #26 & #21)
# ---------------------------------------------------------------------------
def get_master_password(args: Optional[argparse.Namespace] = None) -> Optional[str]:
    """Retrieve master password from environment, password file, stdin pipe, or interactive prompt."""
    # 1. Environment variable
    env_var = os.environ.get("VAULT_MASTER_PASSWORD")
    if env_var:
        return env_var

    # 1b. Password file from environment
    file_path = os.environ.get("VAULT_PASSWORD_FILE")
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.readline().rstrip("\r\n")
        except Exception:
            pass

    # 2. Argument password-env
    if args and getattr(args, "password_env", None):
        val = os.environ.get(args.password_env)
        if val:
            return val

    # 3. Argument password-fd
    if args and getattr(args, "password_fd", None) is not None:
        try:
            with open(args.password_fd, "r", encoding="utf-8") as f:
                return f.readline().rstrip("\r\n")
        except Exception:
            pass

    return None


def unlock_vault(
    master_password: Optional[str] = None,
    allow_pin: bool = True,
) -> Tuple[Optional[Session], Optional[Dict[str, Any]]]:
    """Unlock the vault with lockout protection and optional PIN quick unlock."""
    is_locked, remaining = check_lockout()
    if is_locked:
        err(f"Too many failed unlock attempts. Please wait {remaining} seconds.")
        return None, None

    if not VAULT_FILE.exists():
        err("No vault file found. Starting initial setup.")
        return None, None

    # Try quick unlock via Windows DPAPI & PIN if available
    if allow_pin and is_dpapi_available() and load_config().get("quick_unlock_enabled", False):
        pin = secret_prompt("Enter Quick Unlock PIN (or press Enter for Master Password): ").strip()
        if pin:
            sess = try_quick_unlock(pin)
            if sess:
                try:
                    _, vault = decrypt_container(VAULT_FILE.read_bytes(), "")
                    ok("Quick Unlock successful.")
                    return sess, vault
                except Exception:
                    pass
            warn("Quick Unlock PIN invalid or expired.")

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        pwd = master_password or secret_prompt("Enter Master Password: ")
        if not pwd:
            return None, None
        try:
            with Spinner("Unlocking"):
                sess, vault, needs_migration = open_vault_file(pwd)

            if needs_migration and sess:
                note("Upgrading vault container to Argon2id + AEAD AES-256-GCM...")
                sess = migrate_to_argon2(pwd, vault)
                ok("Vault successfully upgraded.")

            clear_failures()
            return sess, vault
        except Exception:
            record_failure()
            err(f"Incorrect Master Password. (Attempt {attempt}/{MAX_LOGIN_ATTEMPTS})")
            if attempt < MAX_LOGIN_ATTEMPTS:
                time.sleep(attempt)

    err("Authentication failed. Closing vault.")
    return None, None


# ---------------------------------------------------------------------------
# Entry Delivery & Presentation
# ---------------------------------------------------------------------------
def deliver_secret(
    name: str,
    entry: Dict[str, Any],
    show: bool = False,
    show_qr: bool = False,
    show_totp: bool = False,
    raw: bool = False,
    quiet: bool = False,
) -> None:
    sec = entry_secret(entry)
    user = entry.get("username", "")

    if raw:
        sys.stdout.write(sec)
        sys.stdout.flush()
        return

    if show_totp:
        totp_seed = entry_totp(entry)
        if totp_seed:
            display_totp_live(totp_seed, label=f"{name} ({user})")
            return
        else:
            err(f"No TOTP secret configured for '{name}'.")
            return

    if show_qr:
        print_header(f"QR Code · {name}")
        render_qr_ascii(sec)
        return

    if show:
        print(f"\n  {MUTED}Secret for {name}:{RST}")
        print(f"  {INV} {sec} {RST}\n")
        try:
            for remaining in range(SHOW_SECONDS, 0, -1):
                if sys.stdout.isatty():
                    print(f"\r  {WARN}Hiding in {remaining:2d}s (Ctrl+C to hide now){RST}  ", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        wipe_screen()
        if not quiet:
            ok("Secret cleared from display.")
    else:
        cb = {"ok": ok, "err": err, "note": note} if not quiet else None
        copy_with_autoclear(
            sec,
            timeout=CLIPBOARD_TIMEOUT,
            ui_callbacks=cb,
        )


def print_entry_details(name: str, entry: Dict[str, Any], show_secret: bool = False) -> None:
    render_credential_card(name, entry, show_secret=show_secret)


# ---------------------------------------------------------------------------
# Interactive Menu Loop
# ---------------------------------------------------------------------------
def run_vault_app() -> int:
    clear_screen()
    cfg = load_config()
    user_name = cfg.get("name")
    if not user_name:
        print_banner()
        user_name = prompt("Welcome! What should I call you? ").strip() or "Friend"
        save_config(name=user_name)

    print_banner()
    note(f"Welcome back, {user_name}.\n")

    with file_lock():
        session, vault = unlock_vault()
        if session is None or vault is None:
            return 1

        lock = AutoLock(AUTO_LOCK_SECONDS)

        try:
            while True:
                clear_screen()
                print_menu_header(user_name, vault)
                print_menu_options()

                lock.arm()
                choice, timed_out = timed_input(f"  {ACCENT}{G_PROMPT}{RST} ", float(AUTO_LOCK_SECONDS))
                lock.disarm()

                if timed_out or lock.locked:
                    wipe_screen()
                    warn("Vault locked due to inactivity.")
                    re_sess, re_vault = unlock_vault()
                    if not re_sess or not re_vault:
                        return 1
                    session = re_sess
                    vault = re_vault
                    lock.locked = False
                    continue

                choice = choice.strip()
                if choice == "1":
                    add_password_dialog(vault, session)
                    pause()
                elif choice == "2":
                    add_api_key_dialog(vault, session)
                    pause()
                elif choice == "3":
                    import_dialog(vault, session)
                    pause()
                elif choice == "4":
                    get_secret_dialog(vault, session)
                    pause()
                elif choice == "5":
                    edit_entry_dialog(vault, session)
                    pause()
                elif choice == "6":
                    delete_entry_dialog(vault, session)
                    pause()
                elif choice == "7":
                    trash_dialog(vault, session)
                    pause()
                elif choice == "8":
                    health_dashboard_dialog(vault)
                    pause()
                elif choice == "9":
                    totp_generator_dialog(vault)
                    pause()
                elif choice == "10":
                    backup_export_dialog(vault, session)
                    pause()
                elif choice == "11":
                    config_dialog(session)
                    pause()
                elif choice == "0":
                    clear_screen()
                    note(f"Vault securely locked. Goodbye, {user_name}.\n")
                    return 0
                else:
                    time.sleep(0.5)
        finally:
            lock.stop()
            session.close()


def print_menu_header(user_name: str, vault: Dict[str, Any]) -> None:
    h = collect_health(vault)
    score = calculate_health_score(h)
    gauge = render_health_gauge(score, width=10)
    print(f"\n  {BOLD}Password Vault{RST}  {MUTED}{G_DOT}  {user_name}  {G_DOT}  {len(vault)} entries  {G_DOT}  {gauge}{RST}")
    print(f"  {MUTED}{G_H * (term_width() - 4)}{RST}\n")


def print_menu_options() -> None:
    print(f"  {MUTED}ADD & IMPORT{RST}")
    print(f"    {HEAD} 1{RST}  Add Password           {HEAD} 2{RST}  Add API Key            {HEAD} 3{RST}  Import (CSV/Bitwarden)")
    print(f"\n  {MUTED}ACCESS & ORGANIZE{RST}")
    print(f"    {HEAD} 4{RST}  Get Secret / Copy      {HEAD} 5{RST}  Edit Entry             {HEAD} 6{RST}  Delete to Trash")
    print(f"    {HEAD} 7{RST}  Trash & Recovery       {HEAD} 8{RST}  Health & Breach Audit  {HEAD} 9{RST}  TOTP 2FA Authenticator")
    print(f"\n  {MUTED}MAINTENANCE & SECURITY{RST}")
    print(f"    {HEAD}10{RST}  Backup & Export        {HEAD}11{RST}  Settings & Quick PIN   {HEAD} 0{RST}  Lock & Exit\n")
    render_footer_shortcuts([("1-11", "Select"), ("0", "Lock vault")])


# ---------------------------------------------------------------------------
# Dialog Handlers
# ---------------------------------------------------------------------------
def add_password_dialog(vault: Dict[str, Any], session: Session) -> None:
    render_breadcrumbs("Vault", "Add Password")
    print_header("Add Password Entry")
    name = prompt("Service / Website Name (e.g. GitHub): ").strip()
    if not name:
        return
    username = prompt("Username / Email: ").strip()
    url = prompt("Login URL (optional): ").strip()
    known_tags = [t for v in vault.values() for t in v.get("tags", [])]
    tags = prompt_tags(known_tags)

    choice = prompt("(G)enerate strong password or (T)ype your own? [G/t]: ").strip().lower()
    if choice == "t":
        pwd = secret_prompt("Enter Password: ")
        ent, crack_time = calculate_entropy(pwd)
        print(f"  Strength:  {strength_line(pwd)}  ·  {ent} bits ({crack_time})")
        print(f"  Breakdown: {character_breakdown(pwd)}")
    else:
        candidates = generate_candidates(count=3, length=24, symbols=True, exclude_ambiguous=True)
        print(f"\n  {HEAD}Generated Candidates:{RST}")
        for idx, (cand, ent, ct) in enumerate(candidates, 1):
            print(f"    {HEAD}{idx}{RST}  {BOLD}{cand}{RST}  {MUTED}({ent} bits, {ct}){RST}")
        cand_sel = prompt("Select candidate [1-3] or Enter for 1: ").strip()
        try:
            chosen_cand_idx = int(cand_sel) - 1 if cand_sel.isdigit() and 1 <= int(cand_sel) <= 3 else 0
        except Exception:
            chosen_cand_idx = 0
        pwd = candidates[chosen_cand_idx][0]
        note(f"Selected candidate #{chosen_cand_idx + 1}.")

    totp_secret = prompt("TOTP Authenticator Secret (optional, Enter to skip): ").strip()
    fav = confirm_action("Pin as Favorite?", default=False)

    entry = {
        "type": "password",
        "username": username,
        "password": pwd,
        "url": url,
        "tags": tags,
        "favorite": fav,
        "totp_secret": totp_secret,
        "created": date.today().isoformat(),
        "history": [],
        "custom_fields": {},
        "attachments": {},
    }
    vault[name] = validate_entry(entry, name)
    save_vault(session, vault)
    ok(f"Saved '{name}' to vault.")
    copy_with_autoclear(pwd, timeout=CLIPBOARD_TIMEOUT, ui_callbacks={"ok": ok})


def add_api_key_dialog(vault: Dict[str, Any], session: Session) -> None:
    render_breadcrumbs("Vault", "Add API Key")
    print_header("Add API Key Entry")
    name = prompt("Service Name (e.g. OpenAI - Production): ").strip()
    if not name:
        return
    key_val = secret_prompt("Paste API Key: ").strip()
    if not key_val:
        err("Empty key. Aborted.")
        return

    notes_val = prompt("Notes / Project usage: ").strip()
    env_var = prompt("Environment variable name (for `vault run`, e.g. OPENAI_API_KEY): ").strip()
    expires = prompt("Expiry date YYYY-MM-DD (optional): ").strip()

    entry = {
        "type": "api_key",
        "api_key": key_val,
        "notes": notes_val,
        "env": env_var,
        "expires": expires,
        "created": date.today().isoformat(),
        "tags": ["api"],
        "favorite": False,
        "history": [],
        "custom_fields": {},
        "attachments": {},
    }
    vault[name] = validate_entry(entry, name)
    save_vault(session, vault)
    ok(f"Saved API key '{name}'.")


def get_secret_dialog(vault: Dict[str, Any], session: Session) -> None:
    render_breadcrumbs("Vault", "Get Secret")
    query = prompt("Search entry name, username, or tag: ").strip()
    matches, _ = find_matches(vault, query)
    if not matches:
        warn("No matching entries found.")
        return

    chosen = matches[0] if len(matches) == 1 else None
    if not chosen:
        chosen = interactive_select(matches, prompt_text="Select matching entry")
        if not chosen:
            return

    entry = vault[chosen]
    print_entry_details(chosen, entry)
    render_footer_shortcuts([
        ("c", "copy pwd"),
        ("s", "show"),
        ("u", "username"),
        ("o", "open url"),
        ("t", "totp"),
        ("q", "qr"),
        ("e", "edit"),
        ("d", "delete"),
    ])
    mode = prompt("Action [C/s/u/o/t/q/e/d]: ").strip().lower()

    if mode == "s":
        deliver_secret(chosen, entry, show=True)
    elif mode == "u":
        u = entry.get("username", "")
        if u:
            copy_with_autoclear(u, timeout=CLIPBOARD_TIMEOUT, ui_callbacks={"ok": ok})
        else:
            warn(f"No username configured for '{chosen}'.")
    elif mode == "o":
        url = entry.get("url", "")
        if url:
            if open_url(url):
                ok(f"Opened {url} in browser.")
            else:
                err(f"Could not open browser for '{url}'.")
        else:
            warn(f"No URL configured for '{chosen}'.")
    elif mode == "t":
        deliver_secret(chosen, entry, show_totp=True)
    elif mode == "q":
        deliver_secret(chosen, entry, show_qr=True)
    elif mode == "e":
        edit_entry_dialog(vault, session, preselected=chosen)
    elif mode == "d":
        delete_entry_dialog(vault, session, preselected=chosen)
    else:
        deliver_secret(chosen, entry, show=False)


def edit_entry_dialog(
    vault: Dict[str, Any],
    session: Session,
    preselected: Optional[str] = None,
) -> None:
    name = preselected or prompt("Enter name of entry to edit: ").strip()
    if name not in vault:
        warn(f"'{name}' not found.")
        return
    render_breadcrumbs("Vault", "Edit Entry", name)
    entry = vault[name]
    old_entry = dict(entry)
    print_entry_details(name, entry)

    new_user = prompt(f"Username [{entry.get('username', '')}]: ").strip()
    if new_user:
        entry["username"] = new_user

    new_url = prompt(f"URL [{entry.get('url', '')}]: ").strip()
    if new_url:
        entry["url"] = new_url

    if confirm_action("Change password / secret?", default=False):
        old_sec = entry_secret(entry)
        entry.setdefault("history", []).append({
            "secret": old_sec,
            "changed_at": date.today().isoformat(),
        })
        new_sec = secret_prompt("Enter new secret (or press Enter to generate): ")
        if not new_sec:
            new_sec = generate_random_password(length=24, symbols=True, exclude_ambiguous=True)
            ok("Generated new strong password.")
        if entry.get("type") == "api_key":
            entry["api_key"] = new_sec
        else:
            entry["password"] = new_sec

    render_diff(old_entry, entry)
    if confirm_action("Save updated entry?", default=True):
        vault[name] = validate_entry(entry, name)
        save_vault(session, vault)
        ok(f"Updated '{name}'.")
    else:
        warn("Changes discarded.")


def delete_entry_dialog(
    vault: Dict[str, Any],
    session: Session,
    preselected: Optional[str] = None,
) -> None:
    name = preselected or prompt("Name of entry to delete: ").strip()
    if name not in vault:
        warn(f"'{name}' not found.")
        return
    if confirm_action(f"Move '{name}' to encrypted trash?", default=False, danger=True):
        trash_add(session, name, vault.pop(name))
        save_vault(session, vault)
        ok(f"Moved '{name}' to trash (recoverable for {TRASH_DAYS} days).")


def trash_dialog(vault: Dict[str, Any], session: Session) -> None:
    render_breadcrumbs("Vault", "Trash")
    print_header("Trash Management")
    trash = load_trash(session)
    if not trash:
        note("Trash is empty.")
        return

    print("  Deleted Items:")
    items = list(trash.keys())
    for idx, item in enumerate(items, 1):
        del_date = date.fromtimestamp(trash[item].get("deleted_at", 0)).isoformat()
        print(f"    {HEAD}{idx:>2}{RST}  {item:<25} {MUTED}(deleted {del_date}){RST}")

    sub = prompt("\n[R]estore entry, [E]mpty trash, or [B]ack? [r/e/B]: ").strip().lower()
    if sub == "r":
        sel = prompt("Select number to restore: ").strip()
        try:
            item_to_restore = items[int(sel) - 1]
            vault[item_to_restore] = trash.pop(item_to_restore)["entry"]
            save_trash(session, trash)
            save_vault(session, vault)
            ok(f"Restored '{item_to_restore}' to vault.")
        except Exception:
            err("Invalid selection.")
    elif sub == "e" and confirm_action("Permanently purge all deleted items?", default=False, danger=True):
        empty_trash(session)
        ok("Trash emptied.")


def health_dashboard_dialog(vault: Dict[str, Any]) -> None:
    render_breadcrumbs("Vault", "Health & Audit")
    print_header("Vault Health & Breach Audit")
    with Spinner("Analyzing vault health"):
        h = collect_health(vault, check_pwned=False)

    score = calculate_health_score(h)
    print(f"  Security Score:    {render_health_gauge(score, width=15)}")
    print(f"  Total Credentials: {BOLD}{h['total_entries']}{RST}")
    print(f"  Weak Passwords:    {ERR if h['weak'] else OK}{len(h['weak'])}{RST}")
    print(f"  Reused Passwords:  {WARN if h['duplicates'] else OK}{len(h['duplicates'])}{RST}")
    print(f"  Expired Keys:      {ERR if h['expired'] else OK}{len(h['expired'])}{RST}")

    if confirm_action("Run HaveIBeenPwned k-anonymity breach check on all passwords?", default=False):
        with Spinner("Auditing passwords against HIBP"):
            breached = audit_vault_breaches(vault)
        if breached:
            print(f"\n  {ERR}{BOLD}BREACHED PASSWORDS DETECTED:{RST}")
            for name, count in breached:
                print(f"    {ERR}x{RST} {name:<20} found in {BOLD}{count:,}{RST} data breaches!")
        else:
            ok("No stored passwords found in public breach databases.")


def totp_generator_dialog(vault: Dict[str, Any]) -> None:
    print_header("TOTP 2FA Authenticator")
    totp_entries = [k for k, v in vault.items() if entry_totp(v)]
    if not totp_entries:
        warn("No entries have TOTP secrets configured.")
        note("Add a TOTP secret by editing an entry.")
        return

    print("  Available 2FA Accounts:")
    for idx, name in enumerate(totp_entries, 1):
        print(f"    {HEAD}{idx:>2}{RST}  {name}")
    sel = prompt("Choose account: ").strip()
    try:
        chosen = totp_entries[int(sel) - 1]
        display_totp_live(entry_totp(vault[chosen]), label=chosen)
    except Exception:
        pass


def backup_export_dialog(vault: Dict[str, Any], session: Session) -> None:
    print_header("Backup, Export & Emergency Kit")
    print(f"    {HEAD}1{RST}  Create Encrypted Backup")
    print(f"    {HEAD}2{RST}  Export .env Configuration")
    print(f"    {HEAD}3{RST}  Generate Printable Emergency Recovery Kit")
    sub = prompt("Select option [1-3]: ").strip()
    if sub == "1":
        out = export_vault(session, vault)
        ok(f"Encrypted backup saved to: {out}")
    elif sub == "2":
        out = Path.cwd() / ".env"
        cnt = export_dotenv(vault, out)
        ok(f"Exported {cnt} secrets to {out}")
    elif sub == "3":
        kit_path = generate_emergency_kit(session, load_config().get("name", "User"))
        ok(f"Emergency Kit generated at: {kit_path}")


def import_dialog(vault: Dict[str, Any], session: Session) -> None:
    print_header("Import Credentials")
    path_str = prompt("Enter file path (CSV or Bitwarden JSON): ").strip().strip('"')
    p = Path(path_str)
    if not p.is_file():
        err("File not found.")
        return
    shred = confirm("Securely shred source file after successful import?")

    if p.suffix.lower() == ".json":
        added, skipped = import_bitwarden_json(vault, session, p, auto_shred=shred)
    else:
        added, skipped = import_csv(vault, session, p, auto_shred=shred)
    ok(f"Import completed: {added} added, {skipped} skipped.")


def config_dialog(session: Session) -> None:
    print_header("Vault Settings")
    cfg = load_config()
    print(f"  1. Theme:             {cfg.get('theme', 'auto')}")
    print(f"  2. Clipboard Timeout: {CLIPBOARD_TIMEOUT}s")
    print(f"  3. Inactivity Lock:   {AUTO_LOCK_SECONDS}s")
    if is_dpapi_available():
        print(f"  4. Windows Quick PIN: {'Enabled' if cfg.get('quick_unlock_enabled') else 'Disabled'}")

    sub = prompt("Select setting to update (or Enter to cancel): ").strip()
    if sub == "1":
        th = prompt(f"Choose theme ({'/'.join(THEME_NAMES)}/auto): ").strip().lower()
        save_config(theme=th)
        apply_theme(effective_theme(requested=th))
        ok("Theme updated.")
    elif sub == "2":
        to = prompt("Enter seconds for clipboard clearing: ").strip()
        if to.isdigit():
            save_config(clipboard_timeout=int(to))
            ok("Clipboard timeout updated.")
    elif sub == "3":
        to = prompt("Enter seconds before auto-locking: ").strip()
        if to.isdigit():
            save_config(auto_lock_seconds=int(to))
            ok("Auto-lock timeout updated.")
    elif sub == "4" and is_dpapi_available():
        if confirm("Configure Windows DPAPI Quick Unlock PIN?"):
            pin = secret_prompt("Set 4-8 digit PIN: ").strip()
            if pin:
                save_quick_unlock(session, pin)
                save_config(quick_unlock_enabled=True)
                ok("Quick PIN enabled.")


# ---------------------------------------------------------------------------
# Individual Subcommand Dispatchers (cmd_*)
# ---------------------------------------------------------------------------
def cmd_list(argv: Optional[List[str]] = None) -> int:
    import sys
    v = sys.modules.get("vault")
    unlock = getattr(v, "unlock_vault", unlock_vault)
    args = list(argv or [])
    json_output = "--json" in args
    compact = "--compact" in args or "-c" in args
    _, vault = unlock()
    if vault is None:
        return 1
    names = sorted(vault.keys())
    if json_output:
        print(json.dumps(names))
    elif compact:
        for n in names:
            e = vault[n]
            u = e.get("username", "")
            tags = e.get("tags", [])
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            user_str = f" ({u})" if u else ""
            print(f"  {n}{user_str}{tag_str}")
    else:
        for n in names:
            print(f"  {n}")
    return 0


def cmd_open(argv: Optional[List[str]] = None) -> int:
    import sys
    v = sys.modules.get("vault")
    unlock = getattr(v, "unlock_vault", unlock_vault)

    parser = argparse.ArgumentParser(prog="vault open")
    parser.add_argument("name", nargs="?", default="")
    args = parser.parse_args(argv or [])
    if not args.name:
        err("Specify entry name to open.")
        return 1
    session, vault = unlock()
    if not session or not vault:
        return 1
    matches, _ = find_matches(vault, args.name)
    if not matches:
        err(f"Entry '{args.name}' not found.")
        return 1
    entry = vault[matches[0]]
    url = entry.get("url")
    if not url:
        err(f"No URL stored for entry '{matches[0]}'.")
        return 1
    if open_url(url):
        ok(f"Opened {url} in browser.")
        return 0
    else:
        err(f"Could not open browser for '{url}'.")
        return 1


def cmd_delete(argv: Optional[List[str]] = None) -> int:
    import sys
    v = sys.modules.get("vault")
    unlock = getattr(v, "unlock_vault", unlock_vault)
    conf = getattr(v, "confirm", confirm)
    t_add = getattr(v, "trash_add", trash_add)
    s_vault = getattr(v, "save_vault", save_vault)

    args = list(argv or [])
    yes = "--yes" in args or "-y" in args
    names = [a for a in args if not a.startswith("-")]
    if not names:
        err("Specify entry name to delete.")
        return 1
    name = names[0]
    session, vault = unlock()
    if vault is None:
        return 1
    if name not in vault:
        err(f"'{name}' not found.")
        return 1

    if yes or conf(f"Delete '{name}'?"):
        entry = vault.pop(name)
        t_add(session, name, entry)
        s_vault(session, vault)
        ok(f"Moved '{name}' to trash.")
    else:
        warn("Deletion cancelled.")
    return 0


def cmd_get(argv: Optional[List[str]] = None) -> int:
    import sys
    v = sys.modules.get("vault")
    unlock = getattr(v, "unlock_vault", unlock_vault)

    parser = argparse.ArgumentParser(prog="vault get")
    parser.add_argument("name", nargs="?", default="")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--totp", action="store_true")
    parser.add_argument("--qr", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv or [])
    session, vault = unlock()
    if not session or not vault:
        return 1
    matches, _ = find_matches(vault, args.name)
    if not matches:
        err(f"Entry '{args.name}' not found.")
        return 1
    entry = vault[matches[0]]
    if args.json:
        print(json.dumps({matches[0]: entry}, indent=2))
        return 0
    deliver_secret(
        matches[0],
        entry,
        show=args.show,
        show_qr=args.qr,
        show_totp=args.totp,
        raw=args.raw,
        quiet=args.quiet,
    )
    return 0


def cmd_gen(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vault gen")
    parser.add_argument("--length", type=int, default=20)
    parser.add_argument("--profile", choices=["pin", "alphanumeric", "memorable", "max"])
    parser.add_argument("--token", choices=["hex", "base64", "uuid", "alphanumeric"])
    parser.add_argument("--include", type=str, default="")
    parser.add_argument("--exclude", type=str, default="")
    parser.add_argument("--words", type=int, default=0)
    parser.add_argument("--sep", type=str, default="-")
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--no-ambiguous", action="store_true")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args(argv or [])
    if args.token:
        sec = generate_random_token(token_type=args.token, length=args.length)
    elif args.profile:
        sec = generate_with_profile(args.profile, length=args.length if args.length != 20 else None)
    elif args.words > 0:
        sec = generate_passphrase(words=args.words, sep=args.sep)
    else:
        sec = generate_random_password(
            length=args.length,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.no_ambiguous,
            include_chars=args.include or "",
            exclude_chars=args.exclude or "",
        )
    if args.show:
        sys.stdout.write(sec + "\n")
    else:
        copy_with_autoclear(sec, timeout=CLIPBOARD_TIMEOUT, ui_callbacks={"ok": ok})
    return 0


def cmd_benchmark(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    json_out = "--json" in args
    results = benchmark_argon2()
    if json_out:
        sys.stdout.write(json.dumps(results, indent=2) + "\n")
    else:
        sys.stdout.write("\n  Argon2id Hardware Performance Benchmark:\n")
        sys.stdout.write("  " + "-" * 68 + "\n")
        sys.stdout.write(f"  {'Configuration':<34} {'Memory':<10} {'Iterations':<12} {'Latency'}\n")
        sys.stdout.write("  " + "-" * 68 + "\n")
        for r in results:
            cfg_str = str(r["name"])
            mem_str = f"{int(r['memory_mb'])} MB"
            iter_str = f"{int(r['time_cost'])} passes"
            lat_str = f"{float(r['elapsed_ms']):.1f} ms"
            sys.stdout.write(f"  {cfg_str:<34} {mem_str:<10} {iter_str:<12} {lat_str}\n")
        sys.stdout.write("  " + "-" * 68 + "\n\n")
    return 0


def cmd_search(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vault search")
    parser.add_argument("query", nargs="?", default="")
    parser.add_argument("--regex", "-r", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv or [])
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    if not args.query:
        err("Search query or pattern required.")
        return 1
    if args.regex:
        matches, err_msg = find_matches_regex(vault, args.query)
        if err_msg:
            err(err_msg)
            return 1
    else:
        matches, _ = find_matches(vault, args.query)
    if args.json:
        sys.stdout.write(json.dumps(matches, indent=2) + "\n")
    else:
        if not matches:
            note(f"No entries found matching '{args.query}'.")
        else:
            for m in matches:
                sys.stdout.write(f"  {m}\n")
    return 0


def cmd_edit(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    name = args[0] if args else prompt("Entry to edit: ").strip()
    if name not in vault:
        err(f"'{name}' not found.")
        return 1
    edit_entry_dialog(vault, session)
    return 0


def cmd_restore(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    if "--empty" in args:
        empty_trash(session)
        ok("Trash emptied.")
        return 0
    name = args[0] if args else None
    if restore_from_trash(vault, session, name):
        ok(f"Restored '{name}'.")
    else:
        trash_dialog(vault, session)
    return 0


def cmd_import(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vault import")
    parser.add_argument("file", help="Path to import file")
    parser.add_argument("--on-conflict", choices=["skip", "rename", "overwrite"], default="rename")
    parser.add_argument("--shred", action="store_true")
    args = parser.parse_args(argv or [])
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    p = Path(args.file)
    if p.suffix.lower() == ".json":
        added, skipped = import_bitwarden_json(vault, session, p, conflict_mode=args.on_conflict, auto_shred=args.shred)
    else:
        added = import_csv(vault, session, p, on_conflict=args.on_conflict, auto_shred=args.shred)
    ok(f"Imported successfully: {added} entries added.")
    return 0


def cmd_export(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vault export")
    parser.add_argument("file", nargs="?", default="")
    args = parser.parse_args(argv or [])
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    out_path = Path(args.file) if args.file else None
    out = export_vault(session, vault, out_path)
    ok(f"Encrypted export written to: {out}")
    return 0


def cmd_run(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    if "--" not in args:
        err("Usage: vault run KEY1 [KEY2...] -- COMMAND [ARGS...]")
        return 1
    idx = args.index("--")
    keys = args[:idx]
    cmd = args[idx + 1 :]
    if not cmd:
        err("No command specified after '--'.")
        return 1

    session, vault = unlock_vault()
    if not session or not vault:
        return 1

    env_updates: Dict[str, str] = {}
    for k in keys:
        target = k
        as_env = None
        if "=" in k:
            target, as_env = k.split("=", 1)
        matches, _ = find_matches(vault, target)
        if not matches:
            err(f"Secret '{target}' not found in vault.")
            return 1
        entry = vault[matches[0]]
        var_name = as_env or entry.get("env") or to_env_name(matches[0])
        env_updates[var_name] = entry_secret(entry)

    run_env = dict(os.environ)
    run_env.update(env_updates)
    try:
        proc = subprocess.run(cmd, env=run_env)
        return proc.returncode
    except Exception as e:
        err(f"Failed to execute command: {e}")
        return 1


def cmd_doctor(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    json_out = "--json" in args
    deep = "--deep" in args
    session, vault = unlock_vault()
    if not session or not vault:
        return 1
    h = collect_health(vault, check_pwned=deep)
    if json_out:
        print(json.dumps(h, indent=2))
    else:
        ok(f"Diagnostic report: {h['total_entries']} entries, {len(h['weak'])} weak, {len(h['duplicates'])} duplicates.")
    return 0


def cmd_config(argv: Optional[List[str]] = None) -> int:
    session, vault = unlock_vault()
    if session:
        config_dialog(session)
    return 0


def cmd_completion(argv: Optional[List[str]] = None) -> int:
    args = list(argv or [])
    if not args:
        print("Usage: vault completion [powershell|bash|zsh|fish|enable]")
        return 1
    if args[0] == "enable":
        save_config(completion_enabled=True)
        ok("Tab completion enabled.")
        return 0
    print(get_completion_script(args[0]))
    return 0


SUBCOMMANDS = {
    "get": cmd_get,
    "list": cmd_list,
    "gen": cmd_gen,
    "edit": cmd_edit,
    "delete": cmd_delete,
    "restore": cmd_restore,
    "run": cmd_run,
    "import": cmd_import,
    "export": cmd_export,
    "config": cmd_config,
    "doctor": cmd_doctor,
    "completion": cmd_completion,
    "open": cmd_open,
    "benchmark": cmd_benchmark,
    "search": cmd_search,
}
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault",
        description=f"Secure Password Vault v{VERSION} - Zero-trust local password manager",
    )
    parser.add_argument("--version", action="version", version=f"vault {VERSION}")
    parser.add_argument("--theme", choices=THEME_NAMES + ["auto"], help="Set terminal theme")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--password-fd", type=int, help="Read master password from file descriptor")
    parser.add_argument("--password-env", type=str, help="Read master password from specified env var")
    parser.add_argument("--clear-clipboard", action="store_true", help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # get
    p_get = subparsers.add_parser("get", help="Retrieve credentials")
    p_get.add_argument("name", nargs="?", default="", help="Entry name to lookup")
    p_get.add_argument("--url", type=str, help="Search credentials matching URL or domain")
    p_get.add_argument("--show", action="store_true", help="Display secret briefly on screen")
    p_get.add_argument("--totp", action="store_true", help="Display live TOTP 2FA code")
    p_get.add_argument("--qr", action="store_true", help="Display secret as terminal QR code")
    p_get.add_argument("--json", action="store_true", help="Output details in machine-readable JSON")
    p_get.add_argument("--raw", action="store_true", help="Print raw secret only to stdout without newline")
    p_get.add_argument("--quiet", action="store_true", help="Suppress status output")
    p_get.add_argument("--check-age", action="store_true", help="Check credential age and alert if rotation is overdue")

    # list
    p_list = subparsers.add_parser("list", help="List all entry names")
    p_list.add_argument("--tag", type=str, help="Filter entries by tag(s)")
    p_list.add_argument("--fav", action="store_true", help="Show favorites only")
    p_list.add_argument("--regex", "-r", type=str, help="Filter entries by regular expression pattern")
    p_list.add_argument("--expiring-soon", type=int, nargs="?", const=14, help="Show credentials expiring within N days")
    p_list.add_argument("--json", action="store_true", help="Output names in JSON array")
    p_list.add_argument("--compact", "-c", action="store_true", help="Display dense single-line listing")

    # search
    p_search = subparsers.add_parser("search", help="Search vault entries")
    p_search.add_argument("query", nargs="?", default="", help="Search query or pattern")
    p_search.add_argument("--regex", "-r", action="store_true", help="Treat query as regular expression")
    p_search.add_argument("--json", action="store_true", help="Output search results in JSON")

    # open
    p_open = subparsers.add_parser("open", help="Open entry login URL in default web browser")
    p_open.add_argument("name", help="Entry name to open")

    # gen
    p_gen = subparsers.add_parser("gen", help="Generate passwords or passphrases")
    p_gen.add_argument("--length", type=int, default=20, help="Password length")
    p_gen.add_argument("--profile", choices=["pin", "alphanumeric", "memorable", "max"], help="Preset security profile")
    p_gen.add_argument("--token", choices=["hex", "base64", "uuid", "alphanumeric"], help="Generate high-entropy token/key")
    p_gen.add_argument("--include", type=str, default="", help="Characters to force-include in password")
    p_gen.add_argument("--exclude", type=str, default="", help="Characters to exclude from password")
    p_gen.add_argument("--words", type=int, default=0, help="Passphrase word count (uses EFF list)")
    p_gen.add_argument("--sep", type=str, default="-", help="Passphrase separator")
    p_gen.add_argument("--no-symbols", action="store_true", help="Omit symbols from password")
    p_gen.add_argument("--no-ambiguous", action="store_true", help="Omit ambiguous characters (0, O, l, 1, I)")
    p_gen.add_argument("--show", action="store_true", help="Print secret to console")

    # totp
    p_totp = subparsers.add_parser("totp", help="Generate 2FA TOTP code")
    p_totp.add_argument("name", help="Entry name")

    # pwned
    p_pwned = subparsers.add_parser("pwned", help="Check passwords against HaveIBeenPwned")
    p_pwned.add_argument("name", nargs="?", default="", help="Entry name or empty for full audit")

    # emergency-kit
    subparsers.add_parser("emergency-kit", help="Generate printable emergency recovery kit")

    # backup
    p_bak = subparsers.add_parser("backup", help="Create encrypted vault backup")
    p_bak.add_argument("--output", type=Path, help="Target destination path")
    p_bak.add_argument("--compress", "-z", action="store_true", help="Create compressed backup archive (.pvex.gz)")
    p_bak.add_argument("--verify", type=Path, help="Verify integrity of an encrypted backup file")
    p_bak.add_argument("--prune", type=int, nargs="?", const=10, help="Prune older backups exceeding retention count")

    # snapshot
    p_snap = subparsers.add_parser("snapshot", help="Manage rolling vault snapshots")
    p_snap.add_argument("--list", action="store_true", help="List available snapshots")
    p_snap.add_argument("--restore", type=Path, help="Restore vault from snapshot file")

    # clone
    p_clone = subparsers.add_parser("clone", help="Clone an existing credential entry")
    p_clone.add_argument("source", help="Source entry name")
    p_clone.add_argument("destination", help="Destination entry name")

    # rename
    p_ren = subparsers.add_parser("rename", help="Rename an entry")
    p_ren.add_argument("old_name", help="Old entry name")
    p_ren.add_argument("new_name", help="New entry name")

    # notes
    p_not = subparsers.add_parser("notes", help="View or update entry notes")
    p_not.add_argument("name", help="Entry name")
    p_not.add_argument("--set", type=str, help="Update notes text")

    # fav
    p_fav = subparsers.add_parser("fav", help="Toggle entry favorite status")
    p_fav.add_argument("name", help="Entry name")

    # tag
    p_tag = subparsers.add_parser("tag", help="Manage entry tags")
    p_tag.add_argument("action", choices=["add", "remove", "list"], help="Action to perform")
    p_tag.add_argument("tag_name", nargs="?", default="", help="Tag name")
    p_tag.add_argument("entries", nargs="*", help="Entry names to update")

    # clip
    p_clip = subparsers.add_parser("clip", help="Manage clipboard")
    p_clip.add_argument("--clear", action="store_true", help="Clear clipboard immediately")

    # stats
    p_stats = subparsers.add_parser("stats", help="Display vault metrics and statistics")
    p_stats.add_argument("--json", action="store_true", help="Output stats as JSON")

    # audit
    p_aud = subparsers.add_parser("audit", help="Run comprehensive security audit")
    p_aud.add_argument("--entropy", action="store_true", help="Rank entries by Shannon entropy")
    p_aud.add_argument("--similar", action="store_true", help="Detect pattern-based password reuse")
    p_aud.add_argument("--breakdown", action="store_true", help="Detailed health score breakdown")
    p_aud.add_argument("--json", action="store_true", help="Output audit as JSON")

    # export
    p_exp = subparsers.add_parser("export", help="Export credentials")
    p_exp.add_argument("output", nargs="?", type=Path, help="Output destination path")
    p_exp.add_argument("--format", choices=["pvex", "encrypted-json", "csv", "env"], default="pvex", help="Export format")
    p_exp.add_argument("--delimiter", default=",", help="Delimiter for CSV export")
    p_exp.add_argument("--passphrase", default="", help="Passphrase for encrypted-json export")

    # import
    p_imp = subparsers.add_parser("import", help="Import credentials")
    p_imp.add_argument("file", type=Path, help="File to import")
    p_imp.add_argument(
        "--format",
        choices=["auto", "csv", "json", "encrypted-json", "xml", "keepass"],
        default="auto",
        help="Import format",
    )
    p_imp.add_argument("--on-conflict", choices=["skip", "rename", "overwrite"], default="rename", help="Conflict handling strategy")
    p_imp.add_argument("--shred", action="store_true", help="Securely shred source file after import")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run vault diagnostics and health check")
    p_doc.add_argument("--deep", action="store_true", help="Perform deep cryptographic validation")
    p_doc.add_argument("--validate-schema", action="store_true", help="Run comprehensive schema validation against all entries")
    p_doc.add_argument("--json", action="store_true", help="Output report as JSON")

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Benchmark local Argon2id key derivation performance")
    p_bench.add_argument("--json", action="store_true", help="Output benchmark results in JSON")

    # completion
    p_comp = subparsers.add_parser("completion", help="Generate shell tab-completion scripts")
    p_comp.add_argument("shell", choices=["powershell", "bash", "zsh", "fish", "enable"], help="Target shell")

    # git-credential
    p_git = subparsers.add_parser("git-credential", help=argparse.SUPPRESS)
    p_git.add_argument("action", choices=["get", "store", "erase"])

    # host
    subparsers.add_parser("host", help=argparse.SUPPRESS)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)

    if args.clear_clipboard:
        clipboard_cleaner_main()
        return 0

    apply_theme(effective_theme(no_color=args.no_color, requested=args.theme))

    # Fast commands requiring no vault unlock
    if args.command == "completion":
        if args.shell == "enable":
            save_config(completion_enabled=True)
            ok("Tab completion enabled. Syncing index.")
            return 0
        print(get_completion_script(args.shell))
        return 0

    if args.command == "clip":
        if getattr(args, "clear", False):
            clear_clipboard_now()
            ok("Clipboard cleared.")
            return 0

    if args.command == "benchmark":
        results = benchmark_argon2()
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(results, indent=2) + "\n")
        else:
            sys.stdout.write("\n  Argon2id Hardware Performance Benchmark:\n")
            sys.stdout.write("  " + "-" * 68 + "\n")
            sys.stdout.write(f"  {'Configuration':<34} {'Memory':<10} {'Iterations':<12} {'Latency'}\n")
            sys.stdout.write("  " + "-" * 68 + "\n")
            for r in results:
                cfg_str = str(r["name"])
                mem_str = f"{int(r['memory_mb'])} MB"
                iter_str = f"{int(r['time_cost'])} passes"
                lat_str = f"{float(r['elapsed_ms']):.1f} ms"
                sys.stdout.write(f"  {cfg_str:<34} {mem_str:<10} {iter_str:<12} {lat_str}\n")
            sys.stdout.write("  " + "-" * 68 + "\n\n")
        return 0

    if args.command == "gen":
        if getattr(args, "token", None):
            secret_val = generate_random_token(token_type=args.token, length=args.length)
        elif getattr(args, "profile", None):
            secret_val = generate_with_profile(args.profile, length=args.length if args.length != 20 else None)
        elif args.words > 0:
            secret_val = generate_passphrase(words=args.words, sep=args.sep)
        else:
            secret_val = generate_random_password(
                length=args.length,
                symbols=not args.no_symbols,
                exclude_ambiguous=args.no_ambiguous,
                include_chars=getattr(args, "include", "") or "",
                exclude_chars=getattr(args, "exclude", "") or "",
            )
        if args.show:
            sys.stdout.write(secret_val + "\n")
        else:
            copy_with_autoclear(secret_val, timeout=CLIPBOARD_TIMEOUT, ui_callbacks={"ok": ok})
        return 0

    # Commands requiring unlock
    master_pwd = get_master_password(args)

    if args.command == "host":
        session, vault = unlock_vault(master_password=master_pwd, allow_pin=False)
        if session and vault:
            run_native_messaging_host(session, vault)
        return 0

    if args.command == "git-credential":
        session, vault = unlock_vault(master_password=master_pwd)
        if session and vault:
            handle_git_credential(args.action, vault, session)
        return 0

    # Default to interactive menu if no command
    if not args.command:
        if unknown:
            # Quick lookup: vault <query>
            query = " ".join(unknown)
            session, vault = unlock_vault(master_password=master_pwd)
            if not session or not vault:
                return 1
            matches, _ = find_matches(vault, query)
            if not matches:
                err(f"No entry matching '{query}'.")
                return 1
            entry = vault[matches[0]]
            deliver_secret(matches[0], entry, show=False)
            return 0
        return run_vault_app()

    # Commands requiring unlocked vault
    with file_lock():
        session, vault = unlock_vault(master_password=master_pwd)
        if not session or not vault:
            return 1

        if args.command == "get":
            if getattr(args, "url", None):
                domain_query = args.url.lower().strip()
                matches = [k for k, v in vault.items() if domain_query in hostname_of(v.get("url", "")).lower() or domain_query in v.get("url", "").lower()]
            else:
                target = args.name
                if not target:
                    target = prompt("Enter entry name: ").strip()
                matches, _ = find_matches(vault, target)
            if not matches:
                err("No entry found matching query.")
                return 1
            chosen = matches[0]
            entry = vault[chosen]
            if getattr(args, "check_age", False):
                needs_rot, age_days = check_entry_rotation_needed(entry)
                if needs_rot:
                    warn(f"Credential '{chosen}' is {age_days} days old (exceeds recommended {ROTATE_AFTER_DAYS}-day rotation policy).")
                elif age_days > 0:
                    ok(f"Credential '{chosen}' is {age_days} days old (within rotation policy).")
                else:
                    note(f"Credential '{chosen}' has no creation date recorded.")
            if args.json:
                sys.stdout.write(json.dumps({chosen: entry}, indent=2) + "\n")
                return 0
            deliver_secret(
                chosen,
                entry,
                show=args.show,
                show_qr=args.qr,
                show_totp=args.totp,
                raw=getattr(args, "raw", False),
                quiet=getattr(args, "quiet", False),
            )

        elif args.command == "search":
            if getattr(args, "regex", False):
                matches, err_msg = find_matches_regex(vault, args.query)
                if err_msg:
                    err(err_msg)
                    return 1
            else:
                matches, _ = find_matches(vault, args.query)
            if args.json:
                sys.stdout.write(json.dumps(matches, indent=2) + "\n")
            else:
                if not matches:
                    note(f"No entries found matching '{args.query}'.")
                else:
                    for m in matches:
                        sys.stdout.write(f"  {m}\n")
            return 0

        elif args.command == "open":
            matches, _ = find_matches(vault, args.name)
            if not matches:
                err(f"Entry '{args.name}' not found.")
                return 1
            entry = vault[matches[0]]
            url = entry.get("url")
            if not url:
                err(f"No URL stored for entry '{matches[0]}'.")
                return 1
            if open_url(url):
                ok(f"Opened {url} in browser.")
            else:
                err(f"Could not open browser for '{url}'.")
                return 1

        elif args.command == "list":
            entries = vault
            if getattr(args, "regex", None):
                rx_matches, err_msg = find_matches_regex(entries, args.regex)
                if err_msg:
                    err(err_msg)
                    return 1
                entries = {k: entries[k] for k in rx_matches if k in entries}
            if args.tag:
                req_tags = [t.strip().lower() for t in args.tag.split(",") if t.strip()]
                entries = {k: v for k, v in entries.items() if any(rt in [t.lower() for t in v.get("tags", [])] for rt in req_tags)}
            if getattr(args, "expiring_soon", None) is not None:
                days_limit = args.expiring_soon if isinstance(args.expiring_soon, int) else 14
                exp_entries = {}
                for k, v in entries.items():
                    exp_str = v.get("expires", "")
                    if exp_str:
                        d = days_until_expiry(exp_str)
                        if d is not None and 0 <= d <= days_limit:
                            exp_entries[k] = v
                entries = exp_entries
            if args.fav:
                entries = {k: v for k, v in entries.items() if entry_is_favorite(v)}
            names = sorted(entries.keys())
            if args.json:
                sys.stdout.write(json.dumps(names, indent=2) + "\n")
            elif getattr(args, "compact", False):
                for n in names:
                    e = entries[n]
                    u = e.get("username", "")
                    tags = e.get("tags", [])
                    tag_str = f" [{', '.join(tags)}]" if tags else ""
                    user_str = f" ({u})" if u else ""
                    sys.stdout.write(f"  {n}{user_str}{tag_str}\n")
            else:
                for n in names:
                    fav = "* " if entry_is_favorite(entries[n]) else "  "
                    sys.stdout.write(f"  {fav}{n}\n")

        elif args.command == "totp":
            if args.name not in vault:
                err(f"Entry '{args.name}' not found.")
                return 1
            sec = entry_totp(vault[args.name])
            if not sec:
                err(f"No TOTP secret configured for '{args.name}'.")
                return 1
            display_totp_live(sec, label=args.name)

        elif args.command == "pwned":
            if args.name:
                if args.name not in vault:
                    err(f"Entry '{args.name}' not found.")
                    return 1
                sec = entry_secret(vault[args.name])
                cnt = check_password_breach(sec)
                if cnt > 0:
                    err(f"Password for '{args.name}' appeared in {cnt:,} known data breaches!")
                else:
                    ok(f"Password for '{args.name}' is clean (0 breaches detected).")
            else:
                breached = audit_vault_breaches(vault)
                if breached:
                    for n, c in breached:
                        err(f"'{n}' found in {c:,} breaches!")
                else:
                    ok("All vault passwords are clean.")

        elif args.command == "emergency-kit":
            p = generate_emergency_kit(session, load_config().get("name", "User"))
            ok(f"Printable Emergency Kit created: {p}")

        elif args.command == "backup":
            if getattr(args, "verify", None):
                ok_flag, msg, cnt = verify_backup(args.verify, master_pwd)
                if ok_flag:
                    ok(f"Backup verified ({cnt} entries): {msg}")
                    return 0
                else:
                    err(f"Verification failed: {msg}")
                    return 1
            elif getattr(args, "prune", None) is not None:
                retention = args.prune if isinstance(args.prune, int) and args.prune > 0 else 10
                target_dir = args.output.parent if args.output else APP_DIR
                pruned = prune_backups(target_dir, max_backups=retention)
                ok(f"Pruned {len(pruned)} old backup file(s).")
                return 0
            else:
                compress = getattr(args, "compress", False)
                out = export_vault(session, vault, args.output, compress=compress)
                st = "Compressed encrypted backup" if compress else "Encrypted backup"
                ok(f"{st} created: {out}")
                return 0

        elif args.command == "snapshot":
            if getattr(args, "list", False):
                snaps = list_snapshots()
                if not snaps:
                    note("No snapshots found.")
                    return 0
                print("\n  Available Snapshots:")
                for s in snaps:
                    print(f"    - {s['name']}  ({s['size']} bytes, modified {s['modified']})")
                print()
                return 0
            elif getattr(args, "restore", None):
                target_snap = args.restore
                res = restore_snapshot(target_snap)
                ok(f"Restored snapshot to {res}.")
                return 0

        elif args.command == "clone":
            src = args.source
            dst = args.destination
            if src not in vault:
                err(f"Source entry '{src}' not found.")
                return 1
            if dst in vault:
                err(f"Destination entry '{dst}' already exists.")
                return 1
            import copy
            cloned = copy.deepcopy(vault[src])
            cloned["notes"] = f"Cloned from {src}. {cloned.get('notes', '')}".strip()
            vault[dst] = validate_entry(cloned, dst)
            save_vault(session, vault)
            ok(f"Cloned entry '{src}' to '{dst}'.")
            return 0

        elif args.command == "rename":
            old_n = args.old_name
            new_n = args.new_name
            if old_n not in vault:
                err(f"Entry '{old_n}' not found.")
                return 1
            if new_n in vault:
                err(f"Target name '{new_n}' already exists.")
                return 1
            vault[new_n] = vault.pop(old_n)
            save_vault(session, vault)
            ok(f"Renamed entry '{old_n}' to '{new_n}'.")
            return 0

        elif args.command == "notes":
            matches, _ = find_matches(vault, args.name)
            if not matches:
                err(f"Entry '{args.name}' not found.")
                return 1
            target = matches[0]
            entry = vault[target]
            if getattr(args, "set", None) is not None:
                entry["notes"] = args.set
                save_vault(session, vault)
                ok(f"Updated notes for '{target}'.")
                return 0
            else:
                note_text = entry.get("notes", "")
                if not note_text:
                    note(f"No notes recorded for '{target}'.")
                else:
                    print(f"\n  Notes for {target}:\n  {note_text}\n")
                return 0

        elif args.command == "fav":
            matches, _ = find_matches(vault, args.name)
            if not matches:
                err(f"Entry '{args.name}' not found.")
                return 1
            target = matches[0]
            curr = entry_is_favorite(vault[target])
            vault[target]["favorite"] = not curr
            save_vault(session, vault)
            st = "favorited" if not curr else "unfavorited"
            ok(f"Entry '{target}' {st}.")
            return 0

        elif args.command == "tag":
            action = args.action
            tag_val = args.tag_name.strip()
            entries_list = args.entries
            if action == "list":
                all_tags = sorted({t for e in vault.values() if isinstance(e, dict) for t in e.get("tags", [])})
                if not all_tags:
                    note("No tags found.")
                else:
                    print(f"  Tags: {', '.join(all_tags)}")
                return 0
            if not tag_val or not entries_list:
                err("Usage: vault tag <add|remove> <tag_name> <entry1> [entry2...]")
                return 1
            modified_count = 0
            for ent_name in entries_list:
                matches, _ = find_matches(vault, ent_name)
                if not matches:
                    warn(f"Entry '{ent_name}' not found.")
                    continue
                t_name = matches[0]
                e = vault[t_name]
                e_tags = e.setdefault("tags", [])
                if action == "add":
                    if tag_val not in e_tags:
                        e_tags.append(tag_val)
                        modified_count += 1
                elif action == "remove":
                    if tag_val in e_tags:
                        e_tags.remove(tag_val)
                        modified_count += 1
            if modified_count > 0:
                save_vault(session, vault)
                ok(f"Updated tag '{tag_val}' on {modified_count} entry/entries.")
            else:
                note("No entries modified.")
            return 0

        elif args.command == "stats":
            stats = collect_vault_stats(vault)
            if args.json:
                sys.stdout.write(json.dumps(stats, indent=2) + "\n")
            else:
                sys.stdout.write("\n  Vault Statistics:\n")
                sys.stdout.write(f"    Total entries:           {int(stats['total_entries'])}\n")
                sys.stdout.write(f"    Passwords:               {int(stats['passwords'])}\n")
                sys.stdout.write(f"    API keys:                {int(stats['api_keys'])}\n")
                sys.stdout.write(f"    2FA (TOTP) adoption:     {int(stats['totp_enabled'])} ({float(stats['totp_coverage_percent']):.1f}%)\n")
                sys.stdout.write(f"    Favorites:               {int(stats['favorites'])}\n")
                sys.stdout.write(f"    Unique tags:             {int(stats['unique_tags'])}\n")
                sys.stdout.write(f"    Average password length: {float(stats['average_password_length']):.1f} chars\n\n")
            return 0

        elif args.command == "audit":
            if getattr(args, "entropy", False):
                res = calculate_entropy_audit(vault)
                if args.json:
                    sys.stdout.write(json.dumps(res, indent=2) + "\n")
                else:
                    sys.stdout.write("\n  Password Entropy Audit (Ranked weakest to strongest):\n")
                    for r in res[:20]:
                        sys.stdout.write(f"    {str(r['name']):<20} {float(r['entropy']):>5.1f} bits ({str(r['crack_time'])})\n")
                    sys.stdout.write("\n")
                return 0
            elif getattr(args, "similar", False):
                sim = find_similar_passwords(vault)
                if args.json:
                    sys.stdout.write(json.dumps([{"entry1": a, "entry2": b, "similarity": s} for a, b, s in sim], indent=2) + "\n")
                else:
                    if not sim:
                        ok("No dangerously similar password patterns detected.")
                    else:
                        sys.stdout.write("\n  Similar Passwords Detected (Potential Pattern Reuse):\n")
                        for a, b, s in sim:
                            sys.stdout.write(f"    - '{a}' and '{b}' ({int(s)}% similarity)\n")
                        sys.stdout.write("\n")
                return 0
            elif getattr(args, "breakdown", False):
                h = collect_health(vault, check_pwned=False)
                b = calculate_health_score_breakdown(h)
                if args.json:
                    sys.stdout.write(json.dumps(b, indent=2) + "\n")
                else:
                    sys.stdout.write(f"\n  Health Score Breakdown: {int(b['score'])}/100 (Grade: {str(b['grade'])})\n")
                    for k, v in b['deductions'].items():
                        if v > 0:
                            sys.stdout.write(f"    - {str(k).replace('_', ' ').capitalize()}: -{int(v)} pts\n")
                    sys.stdout.write("\n")
                return 0
            else:
                h = collect_health(vault, check_pwned=False)
                score = calculate_health_score(h)
                ok(f"Vault security score: {int(score)}/100 across {len(vault)} entries.")
                return 0

        elif args.command == "export":
            fmt = getattr(args, "format", "pvex") or "pvex"
            out_path = args.output
            if fmt == "encrypted-json":
                passphrase = getattr(args, "passphrase", "")
                if not passphrase:
                    passphrase = secret_prompt("Enter export passphrase: ")
                dest = out_path or (Path.cwd() / "vault-export.json")
                export_encrypted_json(vault, dest, passphrase)
                ok(f"Encrypted JSON envelope written to: {dest}")
            elif fmt == "csv":
                dest = out_path or (Path.cwd() / "vault-export.csv")
                cnt = export_csv(vault, dest, delimiter=getattr(args, "delimiter", ","))
                ok(f"CSV export ({cnt} entries) written to: {dest}")
            elif fmt == "env":
                dest = out_path or (Path.cwd() / ".env")
                cnt = export_dotenv(vault, dest)
                ok(f"Exported {cnt} secrets to: {dest}")
            else:
                out = export_vault(session, vault, out_path)
                ok(f"Encrypted backup created: {out}")
            return 0

        elif args.command == "import":
            p = Path(args.file)
            fmt = getattr(args, "format", "auto")
            is_enc_json = False
            if fmt == "encrypted-json":
                is_enc_json = True
            elif fmt == "auto" and p.suffix.lower() == ".json":
                try:
                    snippet = p.read_text(encoding="utf-8", errors="ignore")[:300]
                    if "passwordvault-encrypted-json" in snippet:
                        is_enc_json = True
                except Exception:
                    pass
            if is_enc_json:
                passphrase = secret_prompt("Enter decryption passphrase for envelope: ")
                added, skipped = import_encrypted_json(vault, session, p, passphrase, on_conflict=args.on_conflict)
                ok(f"Imported {added} entries from encrypted JSON envelope ({skipped} skipped).")
            elif fmt in ("xml", "keepass") or (fmt == "auto" and p.suffix.lower() == ".xml"):
                added, skipped = import_keepass_xml(vault, session, p, on_conflict=args.on_conflict, auto_shred=args.shred)
                ok(f"Imported {added} entries from KeePass XML ({skipped} skipped).")
            elif p.suffix.lower() == ".json":
                added, skipped = import_bitwarden_json(vault, session, p, conflict_mode=args.on_conflict, auto_shred=args.shred)
                ok(f"Imported {added} entries from Bitwarden JSON ({skipped} skipped).")
            else:
                added = import_csv(vault, session, p, on_conflict=args.on_conflict, auto_shred=args.shred)
                ok(f"Imported {added} entries from CSV.")
            return 0

        elif args.command == "doctor":
            if getattr(args, "validate_schema", False):
                valid, errors = validate_vault_schema_detailed({"schema_version": VAULT_SCHEMA_VERSION, "entries": vault})
                if valid:
                    ok(f"Vault schema verification passed (all {len(vault)} entries strictly conform to schema v{VAULT_SCHEMA_VERSION}).")
                    return 0
                else:
                    err(f"Schema verification failed ({len(errors)} error(s) found):")
                    for e in errors:
                        sys.stdout.write(f"    - {e}\n")
                    return 1
            h = collect_health(vault, check_pwned=args.deep)
            if args.json:
                sys.stdout.write(json.dumps(h, indent=2) + "\n")
            else:
                ok(f"Vault operational: {h['total_entries']} entries, {len(h['weak'])} weak, {len(h['duplicates'])} duplicates.")
            return 0

    return 0
