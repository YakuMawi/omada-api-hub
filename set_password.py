#!/usr/bin/env python3
"""Script de configuration du mot de passe d'accès à Omada API Hub.

Usage :
    python3 set_password.py
"""
import getpass
import os
import re
import sys

try:
    import bcrypt
except ImportError:
    sys.exit("Erreur : bcrypt n'est pas installé. Lancez : pip install bcrypt")

ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def read_env():
    if not os.path.exists(ENV_FILE):
        return {}
    data = {}
    with open(ENV_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip()
    return data


def update_env(key, value):
    """Met à jour ou ajoute une clé dans .env."""
    if not os.path.exists(ENV_FILE):
        with open(ENV_FILE, "w") as f:
            f.write(f"{key}={value}\n")
        return

    with open(ENV_FILE, "r") as f:
        content = f.read()

    pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key}={value}", content)
    else:
        content += f"\n{key}={value}\n"

    with open(ENV_FILE, "w") as f:
        f.write(content)


def main():
    print("=== Configuration du mot de passe Omada API Hub ===\n")

    env = read_env()
    current_user = env.get("APP_USERNAME", "admin")

    username = input(f"Nom d'utilisateur [{current_user}] : ").strip()
    if not username:
        username = current_user

    while True:
        password = getpass.getpass("Nouveau mot de passe : ")
        if len(password) < 8:
            print("Le mot de passe doit contenir au moins 8 caractères.")
            continue
        confirm = getpass.getpass("Confirmer le mot de passe : ")
        if password != confirm:
            print("Les mots de passe ne correspondent pas.\n")
            continue
        break

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    update_env("APP_USERNAME", username)
    update_env("APP_PASSWORD_HASH", hashed)

    print(f"\nMot de passe configuré pour l'utilisateur '{username}'.")
    print("Redémarrez l'application pour appliquer les changements.")


if __name__ == "__main__":
    main()
