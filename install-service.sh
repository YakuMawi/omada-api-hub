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

# Install deps
python3 -c "import flask, bcrypt, requests, dotenv" 2>/dev/null || pip3 install -r "$DIR/requirements.txt" -q

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
