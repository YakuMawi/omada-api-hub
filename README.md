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

## Réinitialisation du mot de passe

La réinitialisation de mot de passe fonctionne en deux modes selon la configuration de l'instance.

### Sans serveur SMTP configuré

La vérification se fait par **email de récupération** : l'utilisateur doit saisir son nom de compte et l'adresse email renseignée lors de la création du compte. Si la combinaison correspond, il peut immédiatement définir un nouveau mot de passe.

→ Accessible depuis la page de connexion : **Mot de passe oublié ?**

### Avec serveur SMTP configuré

Un **code à 6 chiffres** valable 15 minutes est envoyé à l'adresse email du compte. L'utilisateur doit le saisir avant de pouvoir définir un nouveau mot de passe.

→ Configurer le SMTP : **⚙ Paramètres → Configuration email (SMTP)**

### Configuration SMTP

Dans **Paramètres → Configuration email (SMTP)**, renseignez :

| Champ | Description |
|-------|-------------|
| Serveur SMTP | ex. `smtp.gmail.com` |
| Port | `587` (STARTTLS) ou `465` (SSL) |
| Utilisateur | Votre adresse email SMTP |
| Mot de passe | Mot de passe ou App Password |
| Expéditeur | Adresse d'envoi (facultatif) |
| STARTTLS | Activé par défaut (recommandé) |

Utilisez le bouton **"Email de test"** pour valider la configuration — l'email est envoyé à l'adresse de récupération de votre compte.

### Email de récupération

Renseignez votre email lors de l'inscription ou dans **⚙ Paramètres → Compte → Modifier l'email de récupération**.

---

## Récupération d'accès (mot de passe oublié sans email)

Si vous n'avez pas d'email de récupération configuré, utilisez l'utilitaire CLI directement sur le serveur :

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
- **Reset de mot de passe** — par email de récupération ou code SMTP
- **Authentification sécurisée** — bcrypt, protection brute-force, CSRF, sessions
- **PWA** — installable sur mobile depuis le navigateur (iOS/Android)
- **Paramètres** — SMTP, version, changement de mot de passe et email

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
- Codes de reset à usage unique, expiry 15 minutes
- Fichiers sensibles exclus du dépôt : `.env`, `users.db`

---

## Licence

MIT © 2025 YakuMawi
