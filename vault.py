import os
import json
import base64
import string
import random
import getpass
import pyperclip
import re  
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- YOUR WATERMARK ---
CREATOR_NAME = "TheSusHero"  # <--- Type your name inside the quotes!

# --- SMART FOLDER SETUP ---
USER_HOME = os.path.expanduser("~")
APP_DIR = os.path.join(USER_HOME, ".local_password_vault")

if not os.path.exists(APP_DIR):
    os.makedirs(APP_DIR)

VAULT_FILE = os.path.join(APP_DIR, "vault.enc")
SALT_FILE = os.path.join(APP_DIR, "salt.key")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")

# --- TERMINAL COLORS ---
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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

# --- PASSWORD GRADER ---
def check_password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1

    if score < 3:
        return "Weak", RED
    elif score < 5:
        return "Moderate", YELLOW
    else:
        return "Strong", GREEN

# --- CRYPTOGRAPHY ENGINE ---
def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

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

# --- THE MAIN APP ---
if __name__ == "__main__":
    clear_screen()
    user_name = get_or_set_username()
    
    # Show the watermark on the login screen
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
            # Show the dashboard watermark above the menu options
            print(f"\n{CYAN}------------------------------------------------------------{RESET}")
            print(f"{YELLOW} Vault Active {CYAN}|{YELLOW} User: {user_name} {CYAN}|{YELLOW} Software by {CREATOR_NAME} {RESET}")
            print(f"{CYAN}------------------------------------------------------------{RESET}")
            print(f"{CYAN}Options:{RESET} [1] Add/Update  [2] Get Password  [3] Delete  [4] Exit")
            choice = input("Choose an option: ")
            
            if choice == '1':
                website = input(f"Website Name (e.g., Netflix): ")
                pwd_choice = input("Do you want to (G)enerate a password or (T)ype your own? [G/T]: ").strip().lower()
                
                if pwd_choice == 't':
                    new_pass = getpass.getpass(f"Enter your existing password for {website} (hidden): ")
                    
                    grade, color = check_password_strength(new_pass)
                    print(f"Password Strength: {color}{grade}{RESET}")
                    
                    if grade == "Weak":
                        confirm = input(f"{YELLOW}Are you sure you want to save a weak password? [Y/N]: {RESET}").strip().lower()
                        if confirm != 'y':
                            print(f"{RED}Aborted saving this password.{RESET}")
                            continue 
                else:
                    new_pass = generate_random_password()
                    print(f"Generated a secure password: {YELLOW}{new_pass}{RESET}")
                
                vault[website] = new_pass
                save_vault(fernet, vault)
                print(f"{GREEN}[SUCCESS] Saved {website} to the vault!{RESET}")
                
            elif choice == '2':
                clear_screen()
                print(f"{CYAN}--- Your Vault Contents ---{RESET}")
                if not vault:
                    print("Vault is empty.")
                else:
                    search_term = input(f"Search for a website {YELLOW}(or press Enter to see all){RESET}: ").strip().lower()
                    print("-" * 27)
                    
                    matching_sites = [site for site in vault.keys() if search_term in site.lower()]
                    
                    if not matching_sites:
                        print(f"{RED}No websites found matching '{search_term}'.{RESET}")
                    else:
                        for site in matching_sites:
                            print(f"- {site}")
                        
                        print("-" * 27)
                        site_to_copy = input("Type the exact website name to copy its password (or press Enter to cancel): ")
                        
                        if site_to_copy in vault:
                            pyperclip.copy(vault[site_to_copy])
                            print(f"{GREEN}[SUCCESS] The password for {site_to_copy} has been copied to your clipboard!{RESET}")
                        elif site_to_copy != "":
                            print(f"{RED}[ERROR] Could not find '{site_to_copy}'. Make sure you typed it exactly.{RESET}")
                
            elif choice == '3':
                clear_screen()
                print(f"{CYAN}--- Delete a Password ---{RESET}")
                
                if not vault:
                    print("Vault is empty. Nothing to delete.")
                else:
                    for site in vault.keys():
                        print(f"- {site}")
                    print("-" * 27)
                    
                    website_to_delete = input(f"Enter the EXACT Website Name you want to delete {YELLOW}(or press Enter to cancel){RESET}: ").strip()
                    
                    if website_to_delete == "":
                        print(f"{YELLOW}Deletion cancelled.{RESET}")
                        continue
                    
                    if website_to_delete in vault:
                        confirm = input(f"{RED}Are you absolutely sure you want to delete '{website_to_delete}'? This cannot be undone. [Y/N]: {RESET}").strip().lower()
                        
                        if confirm == 'y':
                            vault.pop(website_to_delete)
                            save_vault(fernet, vault)
                            print(f"{GREEN}[SUCCESS] Deleted {website_to_delete} from the vault.{RESET}")
                        else:
                            print(f"{YELLOW}Phew! Deletion aborted. Your password is safe.{RESET}")
                    else:
                        print(f"{RED}[ERROR] Could not find '{website_to_delete}'. Remember, it is case-sensitive!{RESET}")
                    
            elif choice == '4':
                clear_screen()
                print(f"{CYAN}Locking vault... Have a great day, {user_name}!{RESET}")
                print(f"{YELLOW}Thank you for using software developed by {CREATOR_NAME}.{RESET}\n")
                break
            else:
                print(f"{RED}Invalid choice. Please type 1, 2, 3, or 4.{RESET}")