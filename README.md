# Secure Password Vault

Secure Password Vault is an enterprise-grade, local-first command-line password manager and secrets vault written in Python. It provides zero-knowledge, authenticated encryption for credentials, API keys, TOTP 2FA seeds, URLs, notes, and environment variables with zero external cloud dependencies.

All cryptographic operations occur entirely in local memory on your machine.

---

## Key Features

- **Authenticated Cryptography**: Encrypted storage using Argon2id key derivation (RFC 9106, 64 MB memory cost) and authenticated AES-256-GCM AEAD encryption.
- **Operating System Hardening**: Native Windows Clipboard History (Win+V) and Cloud Clipboard suppression; in-memory virtual locking to prevent paging sensitive buffers to disk.
- **Quick Unlock**: Windows DPAPI integration with PBKDF2HMAC (100,000 iterations) PIN entropy for fast, secure terminal unlocking.
- **Two-Factor Authentication**: Built-in RFC 6238 TOTP authenticator with live countdowns and terminal ASCII QR code generation.
- **Breach Detection**: Native k-anonymity Have I Been Pwned API checks without transmitting credentials.
- **Disaster Recovery**: Automated rolling snapshots, encrypted backup verification, automatic backup pruning, and printable Emergency Recovery Kits.
- **Advanced Generation**: Cryptographic password generator with preset security profiles (pin, alphanumeric, memorable, max) and EFF wordlist passphrases.
- **Security Auditing**: Shannon entropy calculator, brute-force crack time estimator, password similarity and pattern-reuse detection, and granular health scoring.
- **Broad Interoperability**: Support for authenticated Encrypted JSON Envelopes, Bitwarden JSON, 1Password / LastPass / browser CSV, and `.env` exports.
- **Process Orchestration**: Safe secrets injection via `vault run` without storing plaintext secrets in shell history.
- **Multi-Shell Completion**: Native tab completion for PowerShell, Bash, Zsh, and Fish.

---

## Architecture and Security Model

| Component | Specification |
| --- | --- |
| Primary KDF | Argon2id (RFC 9106, 3 iterations, 64 MB RAM, 4 lanes, 16-byte CSPRNG salt) |
| Container Cipher | AES-256-GCM (12-byte CSPRNG nonce, authenticated additional data) |
| Legacy Compatibility | Scrypt (N=2^17, r=8, p=1) with AES-128-CBC + HMAC-SHA256 (Fernet) |
| PIN Quick Unlock | Windows DPAPI encrypted session key with PBKDF2HMAC (SHA-256, 100k rounds) |
| Memory Security | In-memory recursive zeroization (`wipe_memory`), `VirtualLock` / `mlock` page locking |
| Concurrency Control | Cross-process advisory file locking with timeout protection |
| Storage Integrity | Tamper-evident container magic headers with pre-decryption integrity verification |

---

## Installation

### Prerequisites

- Python 3.10 or newer
- Windows, macOS, or Linux

### Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### Install Launcher (Windows)

Place the project directory or a shortcut to `vault.bat` on your system `PATH`.

```powershell
vault.bat
```

### Build Standalone Executable

To compile a standalone zero-dependency binary using PyInstaller:

```powershell
python -m pip install -r requirements-dev.txt
build_exe.bat
```

The resulting executable is generated at `dist/vault.exe`.

---

## Quick Start

### 1. Initialize Vault

Run the vault without arguments to create your encrypted storage:

```text
vault
```

The setup assistant prompts for:
1. Your display name (used for Emergency Recovery Kits).
2. A strong master password (validated for minimum entropy and length).

### 2. Basic Operations

```powershell
# Add credentials interactively
vault

# Retrieve password to clipboard (auto-cleared after 15 seconds)
vault get GitHub

# Display password temporarily on screen
vault get GitHub --show

# Search credentials by domain or URL
vault get --url github.com

# Open stored login URL in default browser
vault open GitHub

# Generate live TOTP 2FA code
vault totp GitHub
```

---

## Command Reference

### Credential Lookup and Inspection

| Command | Description |
| --- | --- |
| `vault get <name>` | Copy secret to clipboard with automated clearing |
| `vault get <name> --show` | Display secret in terminal with countdown masking |
| `vault get <name> --totp` | Display live TOTP 2FA code with remaining validity |
| `vault get <name> --qr` | Display secret as ASCII QR code in terminal |
| `vault get <name> --raw` | Print raw secret only to stdout (for scripting and pipes) |
| `vault get <name> --check-age` | Check credential age against recommended rotation policy |
| `vault get --url <domain>` | Search credentials matching URL or hostname |
| `vault search <query> [--regex]` | Search entries by keyword or regular expression pattern |
| `vault open <name>` | Launch service login URL in default web browser |
| `vault notes <name>` | View or update entry notes (`--set "text"`) |

### Vault Listing and Filtering

| Command | Description |
| --- | --- |
| `vault list` | List all entry names in alphabetical order |
| `vault list --compact` | Single-line dense view with usernames and tags |
| `vault list --fav` | Filter entries flagged as favorites |
| `vault list --tag <tags>` | Filter entries matching comma-separated tags |
| `vault list --regex <pattern>` | Filter entries using regular expressions |
| `vault list --expiring-soon [days]` | Filter credentials expiring within N days (default: 14) |
| `vault list --json` | Output entry names as a JSON array |

### Password and Token Generation

| Command | Description |
| --- | --- |
| `vault gen` | Generate 20-character high-entropy password |
| `vault gen --length <n>` | Generate custom length password (e.g. `--length 32`) |
| `vault gen --profile <type>` | Generate via preset profile: `pin`, `alphanumeric`, `memorable`, `max` |
| `vault gen --token <type>` | Generate high-entropy API tokens: `hex`, `base64`, `uuid`, `alphanumeric` |
| `vault gen --include <chars>` | Force inclusion of specific character sets |
| `vault gen --exclude <chars>` | Exclude specified characters from generated secrets |
| `vault gen --words <n>` | Generate EFF wordlist passphrase (e.g. `--words 5 --sep "-"`) |
| `vault gen --show` | Print generated secret to stdout instead of copying |

### Entry Management

| Command | Description |
| --- | --- |
| `vault edit [name]` | Interactively edit entry fields with diff review |
| `vault clone <src> <dest>` | Duplicate credential entry preserving metadata |
| `vault rename <old> <new>` | Rename an entry atomically across all indices |
| `vault fav <name>` | Toggle favorite status of an entry |
| `vault tag add <tag> <entries...>` | Bulk assign a tag to multiple entries |
| `vault tag remove <tag> <entries...>` | Bulk remove a tag from entries |
| `vault tag list` | List all unique tags used across the vault |
| `vault delete <name> [--yes]` | Move credential to encrypted trash |
| `vault restore [name]` | Restore entry from encrypted trash |

### Security, Audits, and Diagnostics

| Command | Description |
| --- | --- |
| `vault doctor [--deep] [--json]` | Validate vault integrity, permissions, backups, and security hygiene |
| `vault doctor --validate-schema` | Validate full decrypted schema against version specification |
| `vault benchmark [--json]` | Benchmark local host hardware for Argon2id key derivation |
| `vault audit` | Overall vault security score (0-100%) |
| `vault audit --entropy` | Rank all credentials by Shannon entropy (weakest first) |
| `vault audit --similar` | Detect pattern-based password variations and shared roots |
| `vault audit --breakdown` | Itemized point deduction report and security grade |
| `vault stats [--json]` | Vault composition metrics, 2FA coverage, and tag counts |
| `vault pwned [name]` | Audit passwords against Have I Been Pwned k-anonymity API |
| `vault clip --clear` | Immediately overwrite and zero out system clipboard |

### Backups, Snapshots, and Disaster Recovery

| Command | Description |
| --- | --- |
| `vault backup [--output <path>]` | Create encrypted vault backup archive |
| `vault backup --compress` | Create gzip-compressed encrypted backup archive (`.pvex.gz`) |
| `vault backup --verify <path>` | Verify decryptability and schema integrity of a backup file |
| `vault backup --prune [n]` | Prune oldest backups exceeding retention count (default: 10) |
| `vault snapshot --list` | List timestamped rolling snapshots created before writes |
| `vault snapshot --restore <path>` | Restore snapshot with automated pre-restore safety copy |
| `vault emergency-kit` | Generate printable Emergency Recovery Sheet |

### Import and Export

| Command | Description |
| --- | --- |
| `vault export [--output <path>]` | Export encrypted archive (`.pvex` or `.pvex.gz`) |
| `vault export --format encrypted-json` | Export authenticated AES-256-GCM encrypted JSON envelope |
| `vault export --format csv [--delimiter ,]` | Export vault entries to customizable CSV |
| `vault export --format env` | Export credentials to local `.env` configuration file |
| `vault import <file>` | Import from KeePass 2.x XML, Bitwarden JSON, or browser CSV |
| `vault import <file> --format encrypted-json` | Import authenticated encrypted JSON envelope |

### Automation and Process Injection

| Command | Description |
| --- | --- |
| `vault run KEY1 [KEY2...] -- <command>` | Inject decrypted secrets as environment variables into process |
| `vault completion <shell>` | Generate shell completion (`powershell`, `bash`, `zsh`, `fish`) |
| `vault config` | Configure terminal themes, clipboard delays, and auto-lock timers |

---

## Non-Interactive Automation

For automated headless environments, CI/CD runners, and background services, Password Vault supports non-interactive master password injection without requiring terminal prompts:

1. **Environment Variable**: Set `VAULT_MASTER_PASSWORD`:
   ```bash
   export VAULT_MASTER_PASSWORD="YourMasterPassword"
   vault get DatabasePassword --raw
   ```
2. **Password File**: Set `VAULT_PASSWORD_FILE` pointing to a restricted file:
   ```bash
   export VAULT_PASSWORD_FILE="/etc/secrets/vault.key"
   vault get AWSAccessKey --raw
   ```
3. **File Descriptor**: Pass file descriptor via `--password-fd`:
   ```bash
   vault get DB_PASSWORD --password-fd 3 3< /run/secrets/pwd
   ```

---

## File System and Storage Layout

Vault files are stored in a dedicated local directory with restricted user-only permissions:

- **Windows**: `%USERPROFILE%\.local_password_vault` (hardened via NTFS DACLs / `icacls`)
- **macOS / Linux**: `~/.local_password_vault` (permissions set to `0700`)

```text
~/.local_password_vault/
|-- vault.enc             # Primary authenticated AES-256-GCM vault container
|-- trash.enc             # Encrypted deleted credentials container
|-- config.json           # User preferences (theme, timeouts, security policies)
|-- attempts.json         # HMAC-signed authentication attempt tracking (anti-bruteforce)
|-- quick_unlock.dat      # DPAPI-protected session token (Windows only)
|-- names.txt             # Plaintext index of entry names (optional tab-completion)
\-- snapshots/            # Timestamped pre-write rolling snapshots (*.snap)
```

---

## Testing and Quality Assurance

The repository includes a comprehensive automated test suite covering cryptographic derivation, AEAD encryption, tamper detection, CLI commands, importers, exporters, and UI rendering:

```powershell
# Run full automated test suite (98 tests)
python -m pytest

# Run linting and style validation
python -m ruff check .
```

---

## Security Policy

Security issues may be reported privately through GitHub Private Vulnerability Reporting or via the guidelines outlined in [SECURITY.md](SECURITY.md).

---

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
