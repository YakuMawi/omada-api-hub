# Omada API Hub

Application web multi-utilisateurs pour gérer des contrôleurs Omada SDN via l'OpenAPI.  
Chaque utilisateur dispose de son propre espace isolé avec ses contrôleurs, ses sites et ses clients.

---

## Installation

### Prérequis

- Python 3.10+
- pip3
- git

Testé sur : **Ubuntu 22.04 / 24.04**, Debian 12.

### Démarrage rapide

```bash
git clone https://github.com/YakuMawi/omada-api-hub.git
cd omada-api-hub
./run.sh
```

C'est tout. Le script installe automatiquement les dépendances et génère la configuration au premier lancement.

Ouvrez ensuite **http://\<votre-ip\>:5000** dans votre navigateur, créez votre compte et ajoutez vos contrôleurs Omada.

---

## Démarrage automatique (service systemd)

Pour que l'application démarre automatiquement avec le serveur :

```bash
./install-service.sh
```

Commandes de gestion du service :

```bash
sudo systemctl start omada-api-hub      # Démarrer
sudo systemctl stop omada-api-hub       # Arrêter
sudo systemctl restart omada-api-hub    # Redémarrer
sudo systemctl status omada-api-hub     # Statut
sudo journalctl -u omada-api-hub -f     # Logs en temps réel
```

---

## Mise à jour

```bash
cd omada-api-hub
git pull origin main
sudo systemctl restart omada-api-hub
```

Ou depuis l'interface : **⚙ Paramètres → Vérifier les mises à jour**.

---

## Récupération d'accès (mot de passe oublié)

Si vous n'arrivez plus à vous connecter, utilisez l'utilitaire CLI :

```bash
python3 set_password.py
```

---

## Fonctionnalités

- **Multi-utilisateurs** — inscription, connexion, isolation totale des données par utilisateur
- **Multi-contrôleurs** — chaque utilisateur gère ses propres contrôleurs Omada (MSP ou Customer)
- **Dashboard sites** — liste des sites avec statut et métriques
- **Détail de site** — onglets Appareils, Clients, WAN, WireGuard, Wi-Fi
- **WAN** — détection automatique des ports WAN (En ligne / En backup / Hors ligne)
- **Authentification sécurisée** — bcrypt, protection brute-force, CSRF, sessions
- **PWA** — installable sur mobile depuis le navigateur (iOS/Android)
- **Paramètres** — vérification des mises à jour GitHub, changement de mot de passe

---

## Structure du projet

```
omada-api-hub/
├── app.py                  # Application Flask
├── run.sh                  # Démarrage (installe les deps au premier lancement)
├── install-service.sh      # Installation systemd
├── set_password.py         # Récupération d'accès en ligne de commande
├── requirements.txt
├── VERSION
├── static/                 # CSS, JS, images, PWA
└── templates/              # Pages HTML
```

---

## Sécurité

- Mots de passe hachés avec **bcrypt**
- Protection **brute-force** : 5 tentatives, blocage 5 minutes
- Tokens **CSRF** sur tous les formulaires
- Sessions signées avec une clé secrète auto-générée
- Fichiers sensibles exclus du dépôt : `.env`, `users.db`

---

## Licence

MIT © 2025 YakuMawi
