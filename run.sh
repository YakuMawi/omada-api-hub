#!/bin/bash
set -e
cd "$(dirname "$0")"

# ── 1. Dépendances Python ────────────────────────────────────────────────────
if ! python3 -c "import flask, bcrypt, requests, dotenv" 2>/dev/null; then
    echo "→ Installation des dépendances…"
    pip3 install --user -r requirements.txt -q 2>/dev/null \
        || pip3 install --user --break-system-packages -r requirements.txt -q
fi

# ── 2. Configuration (.env) ──────────────────────────────────────────────────
if [ ! -f .env ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    printf "FLASK_SECRET_KEY=%s\nSESSION_LIFETIME=28800\n" "$SECRET" > .env
    echo "→ Configuration créée (.env)"
fi

# ── 3. Démarrage ─────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "→ Omada API Hub — http://${IP:-localhost}:5000"
exec python3 app.py
