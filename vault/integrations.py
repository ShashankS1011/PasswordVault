# -*- coding: utf-8 -*-
"""Shell completion, Git credential helper, and Browser native messaging (Improvements #22, #23, #29)."""
from __future__ import annotations

import json
import struct
import sys
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Multi-Shell Tab Completion Scripts (Improvement #22)
# ---------------------------------------------------------------------------
POWERSHELL_COMPLETION = r"""
Register-ArgumentCompleter -Native -CommandName vault -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $namesPath = Join-Path $HOME ".local_password_vault\names.txt"
    $subcommands = @("get","list","gen","edit","delete","restore","run","import","export","backup","doctor","config","totp","pwned","emergency-kit","fav","attach","completion","help")

    $elements = $commandAst.ToString().Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($elements.Count -le 2) {
        $subcommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'Command', $_)
        }
    }
    if (Test-Path $namesPath) {
        Get-Content $namesPath | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
"""

BASH_COMPLETION = r"""
_vault_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="get list gen edit delete restore run import export backup doctor config totp pwned emergency-kit fav attach completion help"
    local names_file="$HOME/.local_password_vault/names.txt"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    if [[ -f "$names_file" ]]; then
        local names=$(cat "$names_file")
        COMPREPLY=( $(compgen -W "$names" -- "$cur") )
    fi
}
complete -F _vault_completions vault
"""

ZSH_COMPLETION = r"""
#compdef vault
_vault() {
    local -a commands
    commands=(
        'get:Retrieve credentials'
        'list:List all entries'
        'gen:Generate passwords or passphrases'
        'edit:Modify existing entry'
        'delete:Move entry to trash'
        'restore:Restore entry from trash'
        'totp:Generate two-factor TOTP codes'
        'pwned:Check passwords against data breaches'
        'emergency-kit:Generate emergency recovery sheet'
        'run:Inject secrets into command'
        'backup:Create encrypted backup'
        'doctor:Diagnostics and health checks'
    )
    _describe -t commands 'vault commands' commands
}
"""

FISH_COMPLETION = r"""
complete -c vault -n "__fish_use_subcommand" -a "get list gen edit delete restore totp pwned emergency-kit run backup doctor config"
complete -c vault -n "__fish_seen_subcommand_from get edit delete totp" -a "(cat ~/.local_password_vault/names.txt 2>/dev/null)"
"""


def get_completion_script(shell: str) -> str:
    sh = shell.lower().strip()
    if sh in ("powershell", "pwsh"):
        return POWERSHELL_COMPLETION.strip()
    elif sh == "bash":
        return BASH_COMPLETION.strip()
    elif sh == "zsh":
        return ZSH_COMPLETION.strip()
    elif sh == "fish":
        return FISH_COMPLETION.strip()
    raise ValueError(f"Unsupported shell: {shell}. Choose from: powershell, bash, zsh, fish")


# ---------------------------------------------------------------------------
# Git Credential Helper (Improvement #23)
# ---------------------------------------------------------------------------
def handle_git_credential(action: str, vault: Dict[str, Any], session: Any) -> None:
    """Implement Git Credential Helper interface (RFC for git-credential)."""
    from vault.crypto import save_vault
    from vault.models import entry_secret, validate_entry

    lines = sys.stdin.read().splitlines()
    data: Dict[str, str] = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()

    host = data.get("host", "")
    username = data.get("username", "")
    if not host:
        return

    # Look up by host (e.g. github.com)
    match_entry = None
    target_name = host
    for name, entry in vault.items():
        if host.lower() in name.lower() or host.lower() in str(entry.get("url", "")).lower():
            if not username or entry.get("username", "").lower() == username.lower():
                match_entry = entry
                target_name = name
                break

    if action == "get":
        if match_entry:
            sec = entry_secret(match_entry)
            user = match_entry.get("username", "")
            sys.stdout.write(f"username={user}\npassword={sec}\n\n")
            sys.stdout.flush()

    elif action == "store":
        new_pwd = data.get("password", "")
        if new_pwd and username:
            entry = {
                "type": "password",
                "username": username,
                "password": new_pwd,
                "url": f"https://{host}",
                "notes": "Saved via git-credential-vault",
            }
            vault[target_name] = validate_entry(entry, target_name)
            save_vault(session, vault)

    elif action == "erase":
        if target_name in vault:
            vault.pop(target_name)
            save_vault(session, vault)


# ---------------------------------------------------------------------------
# Browser Native Messaging Host (Improvement #29)
# ---------------------------------------------------------------------------
def run_native_messaging_host(session: Any, vault: Dict[str, Any]) -> None:
    """Host process communicating with Chrome/Firefox extension via stdio."""
    from vault.models import entry_secret

    while True:
        try:
            # Read 4 bytes message length
            raw_len = sys.stdin.buffer.read(4)
            if not raw_len or len(raw_len) < 4:
                break
            msg_len = struct.unpack("=I", raw_len)[0]
            raw_msg = sys.stdin.buffer.read(msg_len).decode("utf-8")
            msg = json.loads(raw_msg)

            action = msg.get("action", "ping")
            response: Dict[str, Any] = {"status": "ok"}

            if action == "ping":
                response["pong"] = True
                response["version"] = "3.4.0"

            elif action == "get":
                url = msg.get("url", "")
                found = None
                for name, entry in vault.items():
                    if url and (url in str(entry.get("url", "")) or name.lower() in url.lower()):
                        found = entry
                        break
                if found:
                    response["username"] = found.get("username", "")
                    response["password"] = entry_secret(found)
                    response["totp"] = found.get("totp_secret", "")
                else:
                    response["status"] = "not_found"

            resp_bytes = json.dumps(response).encode("utf-8")
            sys.stdout.buffer.write(struct.pack("=I", len(resp_bytes)))
            sys.stdout.buffer.write(resp_bytes)
            sys.stdout.buffer.flush()

        except Exception as e:
            err_resp = json.dumps({"status": "error", "message": str(e)}).encode("utf-8")
            sys.stdout.buffer.write(struct.pack("=I", len(err_resp)))
            sys.stdout.buffer.write(err_resp)
            sys.stdout.buffer.flush()
            break
