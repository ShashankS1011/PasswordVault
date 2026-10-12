# Secure Password Vault

Secure Password Vault is a local-first command-line password manager written in
Python. It stores passwords, API keys, notes, usernames, URLs, expiry dates,
and optional environment-variable names in an encrypted local vault.

The project is designed for personal use and offline-first operation. It does
not require an account, a hosted service, or a network connection to unlock
your vault.

> **Important:** This software has not undergone an independent security audit.
> Use a strong master password, keep encrypted backups, and review the source
> code before using it for highly sensitive data.

## Features

- Encrypted local storage with Scrypt and Fernet.
- Password and passphrase generation using Python's `secrets` module.
- Password strength feedback and duplicate-secret detection.
- API-key expiry warnings and rotation reminders.
- Search by entry name, username, notes, or typo-tolerant fuzzy matching.
- Clipboard copying with automatic clearing.
- Brief secret display mode that hides the screen after a timeout.
- Automatic locking after inactivity in the interactive menu.
- Encrypted backups, exports, and a recoverable encrypted trash.
- CSV import for common browser and Bitwarden-style exports.
- `vault run` for injecting selected secrets into a child process.
- Password health dashboard and diagnostic mode.
- Optional PowerShell tab completion using entry names only.
- Standalone Windows executable builds with PyInstaller.

## Security model

### Encryption

New vaults use:

1. A random 16-byte salt.
2. Scrypt for deriving a key from the master password.
3. Fernet authenticated encryption for the vault payload.

Fernet provides confidentiality and tamper detection using AES-128-CBC and
HMAC-SHA256. The Scrypt parameters are stored in the vault header so the file
can be opened with the parameters that were used to create it.

Older vaults created with the legacy PBKDF2 format are upgraded to Scrypt after
successful unlock. The migration keeps safety copies until you confirm that
the upgraded vault works.

### Master password

The master password is not stored anywhere and cannot be recovered or reset.
If it is lost, encrypted vault data and backups cannot be decrypted.

Use a long, unique passphrase rather than reusing a password from another
service. A password manager should not share its master password with any
other account.

### Clipboard and screen display

Copied secrets are cleared automatically when possible. Clipboard behavior
depends on the operating system and installed clipboard tools, so avoid
assuming that a secret is immediately removed on every desktop environment.

The `--show` option displays a secret temporarily. Anyone who can see the
terminal or screen may be able to read it during that interval.

### `vault run` warning

`vault run` passes secrets as environment variables to a child process. This is
convenient for local development, but environment variables may be exposed
through:

- Child processes.
- Debuggers and process-inspection tools.
- Crash reports.
- Application logs.
- CI/CD diagnostics.

Use it only with trusted commands and trusted environments. Do not print the
environment from a command started with `vault run`.

## Requirements

- Python 3.10 or newer.
- `cryptography`.
- `pyperclip` for the preferred clipboard integration.
- Windows, macOS, or Linux.

On Windows, the built-in `clip.exe` fallback may work even when `pyperclip` is
not available.

## Installation

### Install from the repository

From the project directory:

```powershell
python -m pip install -r requirements.txt
```

Run the application:

```powershell
python vault.py
```

On Windows, you can also run:

```powershell
vault.bat
```

To use `vault` from any directory, place the project directory or a shortcut
to `vault.bat` on your `PATH`.

### Build the Windows executable

Install the development and build dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Build:

```powershell
build_exe.bat
```

The executable is written to:

```text
dist\vault.exe
```

The build uses [`vault.spec`](vault.spec). Generated `build/` and `dist/`
directories are ignored by Git.

## First run

Start the vault without arguments:

```powershell
python vault.py
```

On the first run, the application:

1. Creates the local application directory.
2. Asks for a display name.
3. Asks you to create and confirm a master password.
4. Creates an encrypted empty vault.

The master password is required for every future unlock. There is no recovery
mechanism that bypasses encryption.

## Command reference

### Open the interactive menu

```text
vault
```

The menu supports adding passwords and API keys, importing CSV files, finding
and copying secrets, editing entries, deleting entries to trash, checking
vault health, managing backups, changing the master password, and configuring
timeouts.

### Look up and copy a secret

```text
vault get NAME
vault NAME
```

Names may be partial or misspelled. If multiple entries match, the application
shows a selection list.

Show a secret temporarily instead of copying it:

```text
vault get NAME --show
vault NAME --show
```

### List names without secrets

```text
vault list
vault list --json
```

The JSON form prints an array containing entry names only. Secret values,
usernames, notes, and API keys are not included.

### Generate a password

```text
vault gen
vault gen --length 24
vault gen --length 32 --no-symbols
vault gen --length 24 --show
```

Generated passwords are copied to the clipboard by default and are cleared
automatically when possible. Use `--show` to print the generated value instead.

### Generate a passphrase

```text
vault gen --words 6
vault gen --words 8 --sep " "
vault gen --words 6 --show
```

Passphrase generation uses a built-in word list and does not require unlocking
the vault.

### Edit an entry

```text
vault edit
vault edit GitHub
```

The interactive editor can update usernames, URLs, notes, environment-variable
names, expiry dates, passwords, API keys, and entry names.

### Delete and restore entries

Interactive deletion is available from the main menu. For scripting:

```text
vault delete GitHub --yes
```

Deleted entries are moved to encrypted trash rather than immediately removed.
They are retained for the configured trash period and can be restored:

```text
vault restore
vault restore GitHub
vault restore --empty
```

Use `--empty` only when you are certain that no deleted entries are needed.

### Create encrypted backups

Create a backup without overwriting an existing file:

```text
vault backup --output C:\Backups\vault-backup.enc
```

Backups contain encrypted vault data and still require the master password.
Store backups separately from the computer that contains the original vault.
Use more than one backup location if the data is important.

The interactive menu also provides backup, restore, and export options.

### Encrypted export

```text
vault export
vault export C:\Backups\vault-export.pvex
```

Exports are encrypted and can be restored through the backup/restore workflow.
Treat export files as sensitive because anyone who obtains the file and the
master password can decrypt it.

### Import a CSV file

```text
vault import passwords.csv
vault import passwords.csv --on-conflict skip
vault import passwords.csv --on-conflict rename
vault import passwords.csv --on-conflict overwrite
```

The importer recognizes common column names for:

- Entry name or title.
- URL or login URI.
- Username or email.
- Password.
- Notes.

Supported sources include common Chrome, Edge, Firefox, and Bitwarden-style
CSV exports. CSV files contain plaintext passwords. After confirming that the
import succeeded, securely delete the source export and empty the recycle bin
or trash.

### Run a command with secrets

```text
vault run GitHub -- python deploy.py
vault run OpenAI=TAVILY_KEY -- python app.py
```

The first form derives an environment variable name from the entry name. The
second form explicitly chooses the environment variable name. Entry-specific
environment names configured in the vault take precedence when present.

### Configure timeouts and theme

```text
vault config
vault --theme dark
vault --theme light
vault --theme contrast
vault --theme mono
```

Configuration includes clipboard timeout, temporary display duration, automatic
lock timeout, and terminal theme.

### Diagnose the setup

```text
vault doctor
vault doctor --deep
vault doctor --json
```

The diagnostic command checks the vault format, leftover migration files,
failed unlock attempts, backup age, clipboard support, and local setup.
`--deep` unlocks the vault and checks weak or reused secrets, expired API keys,
and rotation reminders. `--json` provides a machine-readable summary without
printing secret values.

### PowerShell completion

Print the completion script:

```powershell
vault completion powershell
```

Enable completion:

```powershell
vault completion enable
```

Completion stores entry names, not secret values, in a plaintext names index.
This still reveals the names of services you use, so enable it only if that
metadata exposure is acceptable.

## Data location and files

The application stores data in:

```text
Windows: %USERPROFILE%\.local_password_vault
Unix:    ~/.local_password_vault
```

Common files include:

| File | Purpose |
| --- | --- |
| `vault.enc` | Main encrypted vault |
| `trash.enc` | Encrypted deleted-entry storage |
| `config.json` | Theme, timeout, display, and backup metadata |
| `attempts.json` | Failed unlock-attempt tracking |
| `names.txt` | Optional plaintext completion index |
| `*.bak` / `*.v1.bak` | Migration or password-change safety copies |

Do not share the application directory publicly. In particular, do not upload
the encrypted vault, backups, or completion index to a public repository.

## Backup and recovery recommendations

Use the following routine:

1. Create the vault with a strong, unique master passphrase.
2. Create an encrypted backup after major changes.
3. Store a backup on a separate disk or trusted private storage location.
4. Periodically test restoring a backup.
5. Keep the master password separate from the backup file.
6. Delete old migration copies after confirming that the current vault works.
7. Run `vault doctor` regularly.

An encrypted backup is not a substitute for a strong master password. If both
the backup and master password are lost, the data cannot be recovered.

## Development

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Run the full test suite:

```powershell
python -m pytest
```

The tests cover password generation, searching, duplicate detection, entry
helpers, encryption round trips, wrong passwords, schema validation, exports,
corrupt trash data, CSV imports, JSON output, and scripted deletion.

Compile the Python sources:

```powershell
python -m py_compile vault.py tests\test_vault.py
```

Build the executable:

```powershell
python -m PyInstaller --noconfirm --clean vault.spec
```

## Project layout

```text
.
├── vault.py              # CLI application
├── vault.bat             # Windows launcher
├── vault.spec            # PyInstaller configuration
├── build_exe.bat         # Windows build helper
├── requirements.txt      # Runtime dependencies
├── requirements-dev.txt  # Test and build dependencies
├── pyproject.toml        # Project metadata and pytest settings
└── tests/
    └── test_vault.py     # Automated tests
```

## Troubleshooting

### Python is not found

Install Python 3.10 or newer and ensure it is available on `PATH`. On Windows,
verify with:

```powershell
python --version
```

### Clipboard is unavailable

Install the runtime dependencies again:

```powershell
python -m pip install -r requirements.txt
```

On Windows, the application may fall back to `clip.exe`. The `--show` option
is available when clipboard integration is not usable.

### The vault cannot be unlocked

Verify that you are using the correct master password. Check the data directory
and run:

```text
vault doctor
```

There is no password-reset procedure. If the vault file is damaged, restore
from an encrypted backup.

### An old-format vault asks for `salt.key`

Legacy vaults need their original salt file for migration. Restore the
corresponding `salt.key` from a trusted backup, then unlock the vault once.
Do not delete migration safety copies until the upgraded vault has been tested.

### A CSV import contains plaintext credentials

This is expected for browser exports. Complete the import, verify the entries,
then securely delete the CSV file and empty the recycle bin or trash.

## Limitations

- There is no account recovery or master-password reset.
- Clipboard clearing depends on operating-system clipboard behavior.
- Terminal display mode cannot protect against screen capture or shoulder
  surfing.
- Environment variables used by `vault run` may be observable by trusted or
  privileged processes.
- The application does not synchronize vaults between devices.
- The project has not been independently security audited.

## License

Add the project's chosen license here before distributing the application.
