#!/usr/bin/env python3
"""Utilitaire CLI — créer ou réinitialiser un compte utilisateur.

Utile si vous êtes bloqué et ne pouvez plus vous connecter via l'interface web.

Usage :
    python3 set_password.py
"""
import getpass
import os
import sqlite3
import sys

try:
    import bcrypt
except ImportError:
    sys.exit("Erreur : bcrypt n'est pas installé. Lancez : pip3 install bcrypt")

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def main():
    if not os.path.exists(DB_FILE):
        sys.exit(f"Base de données introuvable : {DB_FILE}\nLancez l'application au moins une fois avant d'utiliser cet outil.")

    db = sqlite3.connect(DB_FILE)
    users = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()

    print("=== Omada API Hub — Gestion des comptes ===\n")
    if users:
        print("Comptes existants :")
        for u in users:
            print(f"  [{u[0]}] {u[1]}")
    else:
        print("Aucun compte existant.")
    print()

    username = input("Nom d'utilisateur (nouveau ou existant) : ").strip()
    if not username:
        sys.exit("Annulé.")

    while True:
        password = getpass.getpass("Nouveau mot de passe : ")
        if len(password) < 8:
            print("Le mot de passe doit contenir au moins 8 caractères.")
            continue
        confirm = getpass.getpass("Confirmer : ")
        if password != confirm:
            print("Les mots de passe ne correspondent pas.\n")
            continue
        break

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        db.execute("UPDATE users SET password_hash=? WHERE username=?", (pw_hash, username))
        print(f"\nMot de passe mis à jour pour « {username} ».")
    else:
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        print(f"\nCompte « {username} » créé.")
    db.commit()
    db.close()


if __name__ == "__main__":
    main()
