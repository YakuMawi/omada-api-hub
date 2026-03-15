# Omada API Hub

Application web multi-utilisateurs pour gérer des contrôleurs Omada SDN via l'OpenAPI.  
Chaque utilisateur dispose de son propre espace isolé avec ses contrôleurs, ses sites et ses clients.

---

## Fonctionnalités

- **Multi-utilisateurs** — inscription, connexion, isolation totale des données par utilisateur
- **Multi-contrôleurs** — chaque utilisateur peut ajouter plusieurs contrôleurs Omada (MSP ou Customer)
- **Dashboard Sites** — liste et gestion des sites Omada avec statut, appareils et clients
- **Détail de site** — onglets Appareils, Clients, WAN, WireGuard, Wi-Fi, Création de site
- **WAN** — détection automatique des ports WAN (En ligne / En backup / Hors ligne), type de connexion (Fibre SFP+, Ethernet, 5G cellulaire, USB Modem)
- **Authentification sécurisée** — bcrypt, protection brute-force, tokens CSRF, sessions permanentes
- **PWA** — installable sur mobile (iOS / Android) depuis le navigateur
- **Paramètres** — vérification des mises à jour depuis GitHub, changement de mot de passe

---

## Prérequis

| Logiciel | Version minimale |
|----------|-----------------|
| Python   | 3.10+           |
| pip      | 22+             |
| git      | 2.x             |

Systèmes testés : **Ubuntu 22.04 / 24.04**, Debian 12.

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/YakuMawi/omada-api-hub.git
cd omada-api-hub
```

### 2. Installer les dépendances Python

```bash
pip3 install -r requirements.txt
```

> Optionnel mais recommandé : utiliser un environnement virtuel
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -r requirements.txt
> ```

### 3. Créer le fichier de configuration

```bash
cp .env.example .env
```

Éditez `.env` et renseignez une clé secrète Flask :

```env
FLASK_SECRET_KEY=changez-moi-avec-une-valeur-aleatoire-longue

# Durée de session en secondes (28800 = 8h)
SESSION_LIFETIME=28800
```

> **Générer une clé aléatoire :**
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```

> **Note :** `APP_USERNAME` et `APP_PASSWORD_HASH` ne sont plus nécessaires — les comptes sont désormais gérés via l'interface web.

### 4. Démarrer l'application

```bash
./run.sh
```

L'application est accessible sur : **http://\<votre-ip\>:5000**

### 5. Créer votre premier compte

Ouvrez l'application dans votre navigateur, cliquez sur **"Créer un compte"** et choisissez un identifiant et un mot de passe (8 caractères minimum).

### 6. Ajouter un contrôleur Omada

Après connexion, cliquez sur **"Ajouter un contrôleur"** et renseignez :
- URL du contrôleur Omada
- omadacId
- Client ID & Client Secret de votre application OpenAPI

---

## Gestion du service (systemd)

Pour démarrer automatiquement l'application au boot :

### Créer le service

```bash
sudo nano /etc/systemd/system/omada-api-hub.service
```

Contenu :

```ini
[Unit]
Description=Omada API Hub
After=network.target

[Service]
Type=simple
User=openapi
WorkingDirectory=/home/openapi/omada-api-hub
ExecStart=/usr/bin/python3 app.py
Restart=on-failure
RestartSec=5
EnvironmentFile=/home/openapi/omada-api-hub/.env

[Install]
WantedBy=multi-user.target
```

### Commandes de gestion

```bash
# Activer au démarrage
sudo systemctl enable omada-api-hub

# Démarrer
sudo systemctl start omada-api-hub

# Arrêter
sudo systemctl stop omada-api-hub

# Redémarrer
sudo systemctl restart omada-api-hub

# Statut
sudo systemctl status omada-api-hub

# Logs en temps réel
sudo journalctl -u omada-api-hub -f
```

---

## Mise à jour

```bash
cd /home/openapi/omada-api-hub
git pull origin main
pip3 install -r requirements.txt
sudo systemctl restart omada-api-hub
```

Ou depuis l'interface : **Paramètres → Vérifier les mises à jour**.

---

## Structure du projet

```
omada-api-hub/
├── app.py                  # Application Flask principale
├── VERSION                 # Version courante
├── requirements.txt        # Dépendances Python
├── run.sh                  # Script de démarrage rapide
├── set_password.py         # (legacy) utilitaire de configuration
├── .env.example            # Modèle de configuration
├── static/
│   ├── css/style.css
│   ├── img/                # Logo, icônes PWA
│   ├── js/
│   ├── manifest.json       # Manifeste PWA
│   └── sw.js               # Service Worker
└── templates/
    ├── base.html
    ├── app_login.html
    ├── register.html
    ├── settings.html
    ├── login.html
    ├── sites.html
    ├── site_detail.html
    ├── customers.html
    └── create_site.html
```

---

## Sécurité

- Les mots de passe sont hachés avec **bcrypt**
- Protection **brute-force** : 5 tentatives max, blocage 5 minutes
- Tokens **CSRF** sur tous les formulaires
- Sessions Flask signées avec `FLASK_SECRET_KEY`
- Fichiers sensibles exclus du dépôt (`.gitignore`) : `.env`, `users.db`, `.omada-credentials.json`

---

## Licence

MIT © 2025 YakuMawi
