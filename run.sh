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

# ── 3. Certificat HTTPS auto-signé (généré au premier lancement) ─────────────
if [ ! -f ssl/cert.pem ] || [ ! -f ssl/key.pem ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "✗ 'openssl' est requis pour générer le certificat HTTPS."
        echo "  Installe-le : sudo apt install -y openssl"
        exit 1
    fi
    echo "→ Génération du certificat auto-signé (valide 10 ans)…"
    mkdir -p ssl
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout ssl/key.pem -out ssl/cert.pem \
        -subj "/CN=omada-api-hub" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 600 ssl/key.pem
fi

# ── 4. Démarrage ─────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo "→ Omada API Hub — https://${IP:-localhost}"
exec python3 app.py
