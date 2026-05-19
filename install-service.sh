#!/bin/bash
# Installe Omada API Hub comme service systemd (démarre au boot)
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
SVC="omada-api-hub"
USR="$(whoami)"

# Crée le .env si absent (même logique que run.sh)
if [ ! -f "$DIR/.env" ]; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    printf "FLASK_SECRET_KEY=%s\nSESSION_LIFETIME=28800\n" "$SECRET" > "$DIR/.env"
    echo "→ Configuration créée (.env)"
fi

# Install deps (en tant qu'utilisateur courant, sans root)
python3 -c "import flask, bcrypt, requests, dotenv" 2>/dev/null \
    || pip3 install --user -r "$DIR/requirements.txt" -q 2>/dev/null \
    || pip3 install --user --break-system-packages -r "$DIR/requirements.txt" -q

# Génération du certificat HTTPS auto-signé si absent
if [ ! -f "$DIR/ssl/cert.pem" ] || [ ! -f "$DIR/ssl/key.pem" ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "✗ 'openssl' est requis pour générer le certificat HTTPS."
        echo "  Installe-le : sudo apt install -y openssl"
        exit 1
    fi
    echo "→ Génération du certificat auto-signé (valide 10 ans)…"
    mkdir -p "$DIR/ssl"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$DIR/ssl/key.pem" -out "$DIR/ssl/cert.pem" \
        -subj "/CN=omada-api-hub" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 600 "$DIR/ssl/key.pem"
fi

# Autoriser python3 à écouter sur le port 443 (cibler le binaire réel, pas le symlink)
PYTHON_BIN=$(readlink -f "$(which python3)")
sudo setcap 'cap_net_bind_service=+ep' "$PYTHON_BIN"

# Fichier service
cat > /tmp/${SVC}.service << UNIT
[Unit]
Description=Omada API Hub
After=network.target

[Service]
Type=simple
User=${USR}
WorkingDirectory=${DIR}
ExecStart=/usr/bin/python3 ${DIR}/app.py
Restart=on-failure
RestartSec=5
EnvironmentFile=${DIR}/.env
# Autorise l'accès au port 443 sans root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

sudo mv /tmp/${SVC}.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable "$SVC"
sudo systemctl restart "$SVC"

echo ""
echo "✓ Service installé et démarré."
echo ""
echo "  Statut  : sudo systemctl status $SVC"
echo "  Logs    : sudo journalctl -u $SVC -f"
echo "  Arrêter : sudo systemctl stop $SVC"
echo "  Redémarrer : sudo systemctl restart $SVC"
