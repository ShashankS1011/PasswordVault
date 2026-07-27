import base64
import getpass
import json
import os
import random
import re
import string
import subprocess
import sys
import threading
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

# --- YOUR WATERMARK ---
CREATOR_NAME = "TheSusHero"

# --- SMART FOLDER SETUP ---
USER_HOME = os.path.expanduser("~")
APP_DIR = os.path.join(USER_HOME, ".local_password_vault")

if not os.path.exists(APP_DIR):
  os.makedirs(APP_DIR)

VAULT_FILE = os.path.join(APP_DIR, "vault.enc")
SALT_FILE = os.path.join(APP_DIR, "salt.key")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")

# --- TERMINAL COLORS ---
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def clear_screen():
  os.system("cls" if os.name == "nt" else "clear")


def copy_with_autoclear(text, timeout=15):
  """Copies text to clipboard and clears it automatically after `timeout` seconds."""
  pyperclip.copy(text)
  print(
      f"\n{GREEN}[SUCCESS] Password copied to clipboard! (Clears automatically"
      f" in {timeout}s){RESET}"
  )

  def clear():
    time.sleep(timeout)
    if pyperclip.paste() == text:
      pyperclip.copy("")

  threading.Thread(target=clear, daemon=True).start()


def get_or_set_username():
  if os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "r") as f:
      config = json.load(f)
      return config.get("name", "Friend")
  else:
    clear_screen()
    print(f"{CYAN}======================================{RESET}")
    print(f"{YELLOW}      🔒 SECURE PASSWORD VAULT 🔒      {RESET}")
    print(f"{CYAN}        Developed by: {CREATOR_NAME}        {RESET}")
    print(f"{CYAN}======================================{RESET}\n")
    name = input("It looks like you are new here! What is your name? ")
    with open(CONFIG_FILE, "w") as f:
      json.dump({"name": name}, f)
    return name


# --- AUTOMATED EXE BUILDER WITH CUSTOM ICON ---
def build_exe():
  clear_screen()
  print(f"{CYAN}======================================{RESET}")
  print(f"{YELLOW}       🛠️  BUILDING EXE FILE  🛠️       {RESET}")
  print(f"{CYAN}======================================{RESET}\n")

  try:
    import PyInstaller
  except ImportError:
    print(
        f"{YELLOW}[INFO] PyInstaller not found. Installing it"
        f" now...{RESET}\n"
    )
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

  script_path = os.path.abspath(__file__)
  cmd = [sys.executable, "-m", "PyInstaller", "--onefile", script_path]

  # Check for optional app.ico file
  icon_path = os.path.join(os.path.dirname(script_path), "app.ico")
  if os.path.exists(icon_path):
    print(f"{GREEN}[INFO] Custom icon 'app.ico' found! Applying to build...{RESET}")
    cmd.extend(["--icon", icon_path])
  else:
    print(f"{YELLOW}[INFO] No 'app.ico' found in project folder. Using default icon.{RESET}")

  print(f"\n{CYAN}Compiling '{os.path.basename(script_path)}' into an .exe...{RESET}\n")

  try:
    subprocess.run(cmd, check=True)
    print(f"\n{GREEN}[SUCCESS] .exe built successfully!{RESET}")
    print(
        f"{YELLOW}Check the 'dist' folder in your project directory for the executable.{RESET}\n"
    )
  except Exception as e:
    print(f"\n{RED}[ERROR] Build failed: {e}{RESET}\n")

  input("Press Enter to return to main menu...")


# --- PASSWORD GRADER ---
def check_password_strength(password):
  score = 0
  if len(password) >= 8:
    score += 1
  if len(password) >= 12:
    score += 1
  if re.search(r"[A-Z]", password):
    score += 1
  if re.search(r"[a-z]", password):
    score += 1
  if re.search(r"[0-9]", password):
    score += 1
  if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
    score += 1

  if score < 3:
    return "Weak", RED
  elif score < 5:
    return "Moderate", YELLOW
  else:
    return "Strong", GREEN


# --- CRYPTOGRAPHY ENGINE ---
def generate_random_password(length=16):
  characters = string.ascii_letters + string.digits + string.punctuation
  return "".join(random.choice(characters) for _ in range(length))


def get_encryption_key(master_password, salt):
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=480000,
  )
  return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def setup_or_load_salt():
  if os.path.exists(SALT_FILE):
    with open(SALT_FILE, "rb") as f:
      return f.read()
  else:
    new_salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
      f.write(new_salt)
    return new_salt


def load_vault(fernet):
  if not os.path.exists(VAULT_FILE):
    return {}
  with open(VAULT_FILE, "rb") as f:
    encrypted_data = f.read()
  try:
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)
  except InvalidToken:
    print(f"\n{RED}[ERROR] Incorrect Master Password! Vault remains locked.{RESET}")
    return None


def save_vault(fernet, vault_data):
  json_data = json.dumps(vault_data)
  encrypted_data = fernet.encrypt(json_data.encode())
  with open(VAULT_FILE, "wb") as f:
    f.write(encrypted_data)


# --- PASSWORD HEALTH DASHBOARD ---
def run_health_dashboard(vault):
  clear_screen()
  print(f"{CYAN}======================================{RESET}")
  print(f"{YELLOW}      📊 PASSWORD HEALTH DASHBOARD     {RESET}")
  print(f"{CYAN}======================================{RESET}\n")

  if not vault:
    print("Vault is empty. Nothing to analyze.")
    input("\nPress Enter to return...")
    return

  weak_accounts = []
  password_counts = {}

  for site, data in vault.items():
    # Handle legacy single-string passwords safely
    pwd = data["password"] if isinstance(data, dict) else data
    grade, _ = check_password_strength(pwd)

    if grade == "Weak":
      weak_accounts.append(site)

    password_counts[pwd] = password_counts.get(pwd, []) + [site]

  duplicates = {pwd: sites for pwd, sites in password_counts.items() if len(sites) > 1}

  print(f"Total Saved Credentials: {GREEN}{len(vault)}{RESET}\n")

  if weak_accounts:
    print(f"{RED}⚠️ Weak Passwords ({len(weak_accounts)}):{RESET}")
    for site in weak_accounts:
      print(f"  - {site}")
  else:
    print(f"{GREEN}✓ No weak passwords detected!{RESET}")

  print()
  if duplicates:
    print(f"{YELLOW}⚠️ Reused Passwords ({len(duplicates)} groups):{RESET}")
    for pwd, sites in duplicates.items():
      print(f"  - Shared between: {', '.join(sites)}")
  else:
    print(f"{GREEN}✓ No duplicate passwords detected!{RESET}")

  input("\nPress Enter to return...")


# --- BACKUP & RESTORE ---
def backup_vault(fernet):
  backup_path = input("\nEnter path/filename for export (e.g., backup.enc): ").strip()
  if not backup_path:
    return
  try:
    with open(VAULT_FILE, "rb") as src, open(backup_path, "wb") as dst:
      dst.write(src.read())
    print(f"{GREEN}[SUCCESS] Encrypted backup created at '{backup_path}'.{RESET}")
  except Exception as e:
    print(f"{RED}[ERROR] Backup failed: {e}{RESET}")


def restore_vault(fernet):
  backup_path = input("\nEnter path to encrypted backup file: ").strip()
  if not os.path.exists(backup_path):
    print(f"{RED}[ERROR] File does not exist.{RESET}")
    return

  try:
    with open(backup_path, "rb") as f:
      data = f.read()
    decrypted = fernet.decrypt(data).decode()
    restored_data = json.loads(decrypted)

    save_vault(fernet, restored_data)
    print(f"{GREEN}[SUCCESS] Vault restored successfully!{RESET}")
    return restored_data
  except InvalidToken:
    print(f"{RED}[ERROR] Failed to decrypt backup! Master password mismatch or file corrupted.{RESET}")
  except Exception as e:
    print(f"{RED}[ERROR] Restore failed: {e}{RESET}")


# --- VAULT LOGIC ---
def run_vault_app():
  clear_screen()
  user_name = get_or_set_username()

  print(f"{CYAN}======================================{RESET}")
  print(f"{YELLOW}      🔒 SECURE PASSWORD VAULT 🔒      {RESET}")
  print(f"{CYAN}        Developed by: {CREATOR_NAME}        {RESET}")
  print(f"{CYAN}======================================{RESET}\n")
  print(f"{CYAN}Welcome back, {user_name}!{RESET}")

  salt = setup_or_load_salt()
  master_pass = getpass.getpass("Enter your Master Password to unlock the vault: ")

  key = get_encryption_key(master_pass, salt)
  fernet = Fernet(key)
  vault = load_vault(fernet)

  if vault is not None:
    while True:
      print(f"\n{CYAN}------------------------------------------------------------{RESET}")
      print(f"{YELLOW} Vault Active {CYAN}|{YELLOW} User: {user_name} {CYAN}|{YELLOW} Software by {CREATOR_NAME} {RESET}")
      print(f"{CYAN}------------------------------------------------------------{RESET}")
      print(f"{CYAN}Options:{RESET} [1] Add/Update   [2] Get Password   [3] Delete")
      print(f"         [4] Health Check [5] Backup/Restore  [6] Exit")
      choice = input("Choose an option: ").strip()

      if choice == "1":
        website = input("Website Name (e.g., Netflix): ").strip()
        username = input(f"Username/Email for {website}: ").strip()

        pwd_choice = input("Do you want to (G)enerate a password or (T)ype your own? [G/T]: ").strip().lower()

        if pwd_choice == "t":
          new_pass = getpass.getpass(f"Enter password for {website}: ")
          grade, color = check_password_strength(new_pass)
          print(f"Password Strength: {color}{grade}{RESET}")

          if grade == "Weak":
            confirm = input(f"{YELLOW}Are you sure you want to save a weak password? [Y/N]: {RESET}").strip().lower()
            if confirm != "y":
              print(f"{RED}Aborted saving this password.{RESET}")
              continue
        else:
          new_pass = generate_random_password()
          print(f"Generated a secure password: {YELLOW}{new_pass}{RESET}")

        vault[website] = {"username": username, "password": new_pass}
        save_vault(fernet, vault)
        print(f"{GREEN}[SUCCESS] Saved {website} to the vault!{RESET}")

      elif choice == "2":
        clear_screen()
        print(f"{CYAN}--- Your Vault Contents ---{RESET}")
        if not vault:
          print("Vault is empty.")
        else:
          search_term = input(f"Search for a website {YELLOW}(or press Enter to see all){RESET}: ").strip().lower()
          print("-" * 35)

          matching_sites = [s for s in vault.keys() if search_term in s.lower()]

          if not matching_sites:
            print(f"{RED}No websites found matching '{search_term}'.{RESET}")
          else:
            for idx, site in enumerate(matching_sites, start=1):
              entry = vault[site]
              # Backwards compatibility check
              user_str = entry["username"] if isinstance(entry, dict) else "N/A"
              print(f"[{idx}] {site}  {CYAN}(User: {user_str}){RESET}")

            print("-" * 35)
            selection = input("Enter number to copy password (or press Enter to cancel): ").strip()

            if selection.isdigit():
              selected_idx = int(selection) - 1
              if 0 <= selected_idx < len(matching_sites):
                site_key = matching_sites[selected_idx]
                entry = vault[site_key]
                pwd_to_copy = entry["password"] if isinstance(entry, dict) else entry
                copy_with_autoclear(pwd_to_copy)
              else:
                print(f"{RED}[ERROR] Invalid number selection.{RESET}")

      elif choice == "3":
        clear_screen()
        print(f"{CYAN}--- Delete a Password ---{RESET}")

        if not vault:
          print("Vault is empty. Nothing to delete.")
        else:
          sites_list = list(vault.keys())
          for idx, site in enumerate(sites_list, start=1):
            entry = vault[site]
            user_str = entry["username"] if isinstance(entry, dict) else "N/A"
            print(f"[{idx}] {site} {CYAN}(User: {user_str}){RESET}")

          print("-" * 35)
          selection = input(f"Enter the NUMBER to delete {YELLOW}(or press Enter to cancel){RESET}: ").strip()

          if selection.isdigit():
            selected_idx = int(selection) - 1
            if 0 <= selected_idx < len(sites_list):
              website_to_delete = sites_list[selected_idx]
              confirm = input(f"{RED}Are you sure you want to delete '{website_to_delete}'? [Y/N]: {RESET}").strip().lower()

              if confirm == "y":
                vault.pop(website_to_delete)
                save_vault(fernet, vault)
                print(f"{GREEN}[SUCCESS] Deleted {website_to_delete} from vault.{RESET}")
              else:
                print(f"{YELLOW}Deletion cancelled.{RESET}")
            else:
                print(f"{RED}[ERROR] Invalid index number.{RESET}")

      elif choice == "4":
        run_health_dashboard(vault)

      elif choice == "5":
        clear_screen()
        print(f"{CYAN}--- Backup & Restore ---{RESET}")
        print("[1] Create Encrypted Backup")
        print("[2] Restore from Encrypted Backup")
        sub_choice = input("\nChoose an option [1-2]: ").strip()

        if sub_choice == "1":
          backup_vault(fernet)
        elif sub_choice == "2":
          updated_vault = restore_vault(fernet)
          if updated_vault is not None:
            vault = updated_vault

      elif choice == "6":
        clear_screen()
        print(f"{CYAN}Locking vault... Have a great day, {user_name}!{RESET}")
        print(f"{YELLOW}Thank you for using software developed by {CREATOR_NAME}.{RESET}\n")
        break
      else:
        print(f"{RED}Invalid choice. Please select 1 through 6.{RESET}")


# --- STARTUP LAUNCHER MENU ---
if __name__ == "__main__":
  if getattr(sys, "frozen", False):
    run_vault_app()
  else:
    while True:
      clear_screen()
      print(f"{CYAN}======================================{RESET}")
      print(f"{YELLOW}      🔒 SECURE PASSWORD VAULT 🔒      {RESET}")
      print(f"{CYAN}        Developed by: {CREATOR_NAME}        {RESET}")
      print(f"{CYAN}======================================{RESET}\n")
      print(f"{CYAN}How would you like to proceed?{RESET}\n")
      print("  [1] Run Vault App (Inside Code Editor)")
      print("  [2] Generate / Build new .exe file")
      print("  [3] Exit\n")

      mode = input("Choose an option [1-3]: ").strip()

      if mode == "1":
        run_vault_app()
        break
      elif mode == "2":
        build_exe()
      elif mode == "3":
        print(f"\n{YELLOW}Goodbye!{RESET}\n")
        break
      else:
        print(f"\n{RED}Invalid choice. Please select 1, 2, or 3.{RESET}")
        input("Press Enter to try again...")