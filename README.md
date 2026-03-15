# 🔒 Secure Password Vault

A high-security, local-first password manager built with Python. This application allows users to securely store, generate, and manage their credentials using industry-standard AES-256 encryption.

---

## ✨ Features

* **AES-256 Encryption:** Uses the `cryptography` library with PBKDF2 key derivation to ensure your data is unreadable without your Master Password.
* **Smart Storage:** Automatically creates a hidden directory in the user's home folder to store encrypted data, keeping the desktop clean.
* **Password Grader:** Real-time analysis of password strength with visual color-coded feedback (Weak, Moderate, Strong).
* **Secure Clipboard Integration:** Copy passwords directly to your clipboard with one click—no need to display them on screen.
* **Search Functionality:** Quickly filter through dozens of entries to find exactly what you need.
* **Personalized Experience:** Features a custom greeting system and a creator watermark/dashboard.

---

## 🚀 How to Use

### For Regular Users
If you have the `.exe` file:
1. Double-click `vault.exe`.
2. On the first run, enter your name to personalize your vault.
3. Set a **Master Password**. *Note: Do not forget this! It is the only way to decrypt your data.*
4. Use the menu options (1-4) to manage your passwords.
