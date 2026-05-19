#!/bin/bash
# install-lxc.sh — Installation autonome d'Omada API Hub sur un LXC vierge
# Usage : sur un LXC Ubuntu 22.04+/Debian 12, en root :
#   bash install-lxc.sh
#
# Crée un utilisateur dédié 'omada', clone le repo, installe le service systemd
# et ouvre le port 443.

set -e

REPO_URL="https://github.com/YakuMawi/omada-api-hub.git"
APP_USER="omada"
APP_HOME="/home/${APP_USER}"
APP_DIR="${APP_HOME}/omada-api-hub"

# ── 0. Vérifications ─────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "✗ Ce script doit être lancé en root (ou via sudo)."
    exit 1
fi

if ! grep -qiE "ubuntu|debian" /etc/os-release; then
    echo "⚠ Distribution non testée (recommandé : Ubuntu 22.04+/Debian 12)."
    read -p "Continuer quand même ? [y/N] " ok
    [ "$ok" = "y" ] || exit 1
fi

echo "→ Mise à jour des paquets système…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git sudo libcap2-bin ca-certificates curl openssl

# ── 1. Utilisateur dédié ─────────────────────────────────────────────────────
if ! id "$APP_USER" >/dev/null 2>&1; then
    echo "→ Création de l'utilisateur '$APP_USER'…"
    useradd -m -s /bin/bash "$APP_USER"
fi

# Sudo NOPASSWD limité aux commandes nécessaires (setcap, systemctl, mv vers /etc/systemd)
cat > /etc/sudoers.d/${APP_USER}-omada <<EOF
${APP_USER} ALL=(root) NOPASSWD: /usr/sbin/setcap, /sbin/setcap, /bin/setcap, /usr/bin/setcap, /bin/mv /tmp/omada-api-hub.service /etc/systemd/system/, /bin/systemctl daemon-reload, /bin/systemctl enable omada-api-hub, /bin/systemctl restart omada-api-hub, /bin/systemctl start omada-api-hub, /bin/systemctl stop omada-api-hub, /bin/systemctl status omada-api-hub, /bin/journalctl -u omada-api-hub *
EOF
chmod 440 /etc/sudoers.d/${APP_USER}-omada

# ── 2. Clone du dépôt ────────────────────────────────────────────────────────
if [ -d "$APP_DIR/.git" ]; then
    echo "→ Dépôt existant — git pull…"
    sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only
else
    echo "→ Clone de $REPO_URL…"
    sudo -u "$APP_USER" git clone "$REPO_URL" "$APP_DIR"
fi

# ── 3. Installation du service ───────────────────────────────────────────────
echo "→ Lancement de install-service.sh…"
sudo -u "$APP_USER" bash -c "cd '$APP_DIR' && ./install-service.sh"

# ── 4. Récap ─────────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ✓ Omada API Hub installé"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Accès    : https://${IP:-<ip-du-lxc>}"
echo "  (certificat auto-signé, accepter l'avertissement du navigateur)"
echo ""
echo "  Statut   : systemctl status omada-api-hub"
echo "  Logs     : journalctl -u omada-api-hub -f"
echo "  Update   : sudo -u ${APP_USER} bash -c 'cd ${APP_DIR} && git pull && sudo systemctl restart omada-api-hub'"
echo ""
echo "  Données  : ${APP_DIR}"
echo "════════════════════════════════════════════════════════════════"
