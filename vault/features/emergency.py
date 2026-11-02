# -*- coding: utf-8 -*-
"""Emergency Kit generator (Improvement #16)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vault.constants import APP_DIR, VERSION


def generate_emergency_kit(session: Any, owner_name: str = "User") -> Path:
    """Generate a printable HTML and Markdown emergency recovery sheet."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    salt_hex = session.salt.hex() if hasattr(session, "salt") else "N/A"
    kdf_info = (
        f"Argon2id (time={session.argon2_time}, mem={session.argon2_mem}KB, lanes={session.argon2_lanes})"
        if getattr(session, "kdf_type", "") == "argon2"
        else f"Scrypt (N=2^{getattr(session, 'n_log2', 17)}, r={getattr(session, 'r', 8)}, p={getattr(session, 'p', 1)})"
    )

    out_file = APP_DIR / "emergency_kit.html"
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Password Vault - Emergency Kit</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #222; }}
  .box {{ border: 2px solid #0066cc; border-radius: 8px; padding: 24px; max-width: 680px; margin: 0 auto; }}
  h1 {{ color: #0066cc; margin-top: 0; font-size: 24px; }}
  .meta {{ font-size: 14px; color: #555; margin-bottom: 20px; }}
  .field {{ margin: 16px 0; }}
  .label {{ font-size: 12px; font-weight: bold; text-transform: uppercase; color: #777; }}
  .val {{ font-family: monospace; background: #f4f6f8; padding: 8px 12px; border-radius: 4px; border: 1px solid #ddd; word-break: break-all; margin-top: 4px; }}
  .write-box {{ border: 2px dashed #999; border-radius: 6px; height: 70px; margin-top: 6px; }}
  .instructions {{ background: #fff8e6; border-left: 4px solid #f59f00; padding: 12px 16px; margin: 20px 0; font-size: 13px; }}
  @media print {{ body {{ margin: 0; }} .box {{ border-color: #000; }} }}
</style>
</head>
<body>
<div class="box">
  <h1>Secure Password Vault · Emergency Kit</h1>
  <div class="meta">Generated for <b>{owner_name}</b> on {now} · v{VERSION}</div>

  <div class="instructions">
    <b>Important:</b> Print this document and store it in a secure location (such as a fireproof safe).
    Do NOT store the unencrypted emergency kit on a public computer or cloud storage.
  </div>

  <div class="field">
    <div class="label">Vault Salt (Hexadecimal)</div>
    <div class="val">{salt_hex}</div>
  </div>

  <div class="field">
    <div class="label">Key Derivation Specification</div>
    <div class="val">{kdf_info}</div>
  </div>

  <div class="field">
    <div class="label">Primary Master Passphrase (handwritten copy)</div>
    <div class="write-box"></div>
  </div>

  <div class="field">
    <div class="label">Recovery Instructions</div>
    <p style="font-size: 13px; color: #444; line-height: 1.5;">
      To restore this vault on a new computer:
      <br>1. Install Python 3.10+ and Password Vault (`pip install secure-password-vault`).
      <br>2. Copy your encrypted backup or <code>vault.enc</code> to <code>~/.local_password_vault/</code>.
      <br>3. Run <code>vault restore &lt;backup_file&gt;</code> and enter your Master Passphrase.
    </p>
  </div>
</div>
</body>
</html>
"""
    out_file.write_text(html_content, encoding="utf-8")
    return out_file
