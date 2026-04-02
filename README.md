# Omada API Hub

<p align="center">
  <img src="static/img/logo.svg" alt="Omada API Hub" height="80">
</p>

<p align="center">
  Application web multi-utilisateurs pour gérer des contrôleurs <strong>TP-Link Omada SDN</strong> via l'OpenAPI.<br>
  Chaque utilisateur dispose de son propre espace isolé avec ses contrôleurs, ses sites et ses clients.
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#fonctionnalités">Fonctionnalités</a> •
  <a href="#modes-de-connexion">Modes</a> •
  <a href="#sécurité">Sécurité</a> •
  <a href="#mise-à-jour">Mise à jour</a>
</p>

---

## Installation

### Prérequis

- Python 3.10+
- pip3
- git

Testé sur : **Ubuntu 22.04 / 24.04 / 25.04**, Debian 12.

### Démarrage rapide

```bash
git clone https://github.com/YakuMawi/omada-api-hub.git
cd omada-api-hub
./run.sh
```

C'est tout. Le script installe automatiquement les dépendances et génère la configuration au premier lancement.

Ouvrez ensuite **https://\<votre-ip\>** dans votre navigateur (port 443 HTTPS), créez votre compte et ajoutez vos contrôleurs Omada.

> Le certificat est auto-signé : acceptez l'avertissement du navigateur au premier accès.

---

## Fonctionnalités

### Gestion multi-contrôleurs

- **Mode MSP** — gestion multi-clients avec vue clients, création/suppression en masse de clients et de sites
- **Mode Standard** — contrôleur unique, accès direct aux sites sans passer par la vue clients
- **Multi-contrôleurs** — chaque utilisateur gère autant de contrôleurs Omada que souhaité
- **Profils sauvegardés** — identifiants mémorisés, connexion rapide en un clic

### Gestion des clients (MSP)

- **Liste des clients** avec recherche, tri (nom, nombre de sites, API configurée) et compteur
- **Vue cartes ou tableau** — basculer entre grille de cartes et tableau compact
- **Création en masse** — préfixe + nombre + incrémentation automatique
- **Suppression en masse** — sélection par checkbox, confirmation par mot-clé
- **Authorization Code** — support du flow OAuth Authorization Code pour les opérations MSP (create/delete clients)
- **Connexion rapide** — clic direct pour accéder à un client si les credentials sont sauvegardées
- **Suppression totale des sites** — forget devices + suppression de tous les sites d'un client en une opération

### Gestion des sites

- **Dashboard sites** — liste de tous les sites avec statut, région, type, nombre d'équipements
- **Création de site** — formulaire avec auto-détection de la timezone et de la région depuis un site existant
- **Création en masse** — préfixe, nombre, incrémentation, mêmes paramètres pour tous les sites
- **Suppression en masse** — sélection multiple, confirmation sécurisée, progression en temps réel
- **Forget devices en masse** — oublier les équipements de plusieurs sites sélectionnés sans supprimer les sites
- **Adoption de devices** — importer des équipements par adresse MAC
- **Export des devices** — exporter la liste des équipements de tous les sites (CSV)

### Détail de site

- **Onglet Appareils** — liste des équipements avec statut, modèle, firmware, IP, MAC
- **Onglet Clients** — liste des clients connectés par AP/switch
- **Onglet WAN** — détection automatique des ports WAN (En ligne / En backup / Hors ligne), configuration WAN
- **Onglet WireGuard** — gestion des tunnels VPN WireGuard (liste, modification, suppression)
- **Onglet Wi-Fi (SSID)** — gestion des réseaux Wi-Fi par WLAN, activation/désactivation des SSID en un clic avec mise à jour visuelle instantanée

### Interface utilisateur

- **Mode sombre** — bascule lune/soleil dans la navbar, choix dans Paramètres (Clair / Sombre / Suivre le système)
- **Navbar contextuelle** — breadcrumb adaptatif selon le mode (MSP/Client/Standard)
- **PWA** — installable sur mobile depuis le navigateur (iOS/Android)
- **Responsive** — interface adaptée mobile, tablette et desktop

### Administration

- **Multi-utilisateurs** — inscription, connexion, isolation totale des données par utilisateur
- **Paramètres** — apparence, SMTP, version, changement de mot de passe et email de récupération
- **Mise à jour depuis l'interface** — Paramètres → Version & Mises à jour → Mettre à jour
- **Reset de mot de passe** — par email de récupération ou code SMTP à 6 chiffres

---

## Modes de connexion

### Mode MSP

Pour les contrôleurs en mode **MSP (Managed Service Provider)** :

1. Sélectionnez "MSP" sur la page de connexion
2. Renseignez l'URL du contrôleur, l'ID MSP, et les credentials de l'app **Client Credentials**
3. (Optionnel) Ajoutez les credentials de l'app **Authorization Code** + identifiants admin pour créer/supprimer des clients

Le flow OAuth Authorization Code s'exécute automatiquement en 3 étapes :
- Login → CSRF token + session
- Authorization → code (valide 2 min)
- Token exchange → access token (valide 2h, rafraîchi automatiquement)

### Mode Standard

Pour les contrôleurs **non-MSP** (accès direct aux sites) :

1. Sélectionnez "Standard (non-MSP)" sur la page de connexion
2. Renseignez l'URL du contrôleur, le Controller ID, et les credentials de l'app Client Credentials
3. Vous accédez directement aux sites sans passer par la vue clients

---

## HTTPS

L'application démarre en **HTTPS sur le port 443** grâce à un certificat auto-signé généré automatiquement dans `ssl/` au premier lancement.

```bash
# Autoriser Python à écouter sur le port 443 sans root (une seule fois)
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f $(which python3))
```

Le certificat est valable 10 ans.

---

## Démarrage automatique (systemd)

```bash
./install-service.sh
```

Commandes de gestion :

```bash
sudo systemctl start omada-api-hub      # Démarrer
sudo systemctl stop omada-api-hub       # Arrêter
sudo systemctl restart omada-api-hub    # Redémarrer
sudo systemctl status omada-api-hub     # Statut
sudo journalctl -u omada-api-hub -f     # Logs en temps réel
```

---

## Mise à jour

Depuis l'interface : **Paramètres → Version & Mises à jour → Mettre à jour**.

Ou en ligne de commande :

```bash
cd omada-api-hub
git pull origin main
sudo systemctl restart omada-api-hub
```

---

## Réinitialisation du mot de passe

### Sans serveur SMTP configuré

La vérification se fait par **email de récupération** : l'utilisateur saisit son nom de compte et l'adresse email renseignée à l'inscription. Si la combinaison correspond, il peut définir un nouveau mot de passe.

> Accessible depuis la page de connexion : **Mot de passe oublié ?**

### Avec serveur SMTP configuré

Un **code à 6 chiffres** valable 15 minutes est envoyé par email.

> Configurer le SMTP : **Paramètres → Configuration email (SMTP)**

| Champ | Description |
|-------|-------------|
| Serveur SMTP | ex. `smtp.gmail.com` |
| Port | `587` (STARTTLS) ou `465` (SSL) |
| Utilisateur | Votre adresse email SMTP |
| Mot de passe | Mot de passe ou App Password |
| Expéditeur | Adresse d'envoi (facultatif) |
| STARTTLS | Activé par défaut (recommandé) |

### Récupération d'accès (sans email configuré)

```bash
python3 set_password.py
```

---

## Structure du projet

```
omada-api-hub/
├── app.py                  # Application Flask principale
├── config.py               # Constantes partagées (chemins, repo)
├── db.py                   # Helpers base de données et SMTP
├── blueprints/
│   └── auth.py             # Blueprint authentification (register, login, reset)
├── run.sh                  # Démarrage (installe les deps au premier lancement)
├── install-service.sh      # Installation systemd
├── set_password.py         # Récupération d'accès CLI
├── requirements.txt        # Dépendances Python
├── VERSION                 # Version courante
├── ssl/                    # Certificat auto-signé (généré automatiquement)
│   ├── cert.pem
│   └── key.pem
├── static/
│   ├── css/style.css       # Styles (thème clair/sombre)
│   ├── js/app.js           # JavaScript partagé
│   ├── img/                # Logo, favicon, icône PWA
│   ├── manifest.json       # PWA manifest
│   └── sw.js               # Service worker PWA
└── templates/
    ├── base.html            # Layout principal (navbar, dark mode)
    ├── login.html           # Connexion contrôleur Omada (MSP/Standard)
    ├── app_login.html       # Connexion à l'application
    ├── register.html        # Inscription
    ├── forgot_password.html # Mot de passe oublié
    ├── reset_password.html  # Réinitialisation
    ├── customers.html       # Liste clients MSP (cartes/tableau, recherche, tri)
    ├── sites.html           # Liste des sites (bulk create/delete/forget/export)
    ├── create_site.html     # Formulaire de création de site
    ├── site_detail.html     # Détail site (devices, clients, WAN, WireGuard, Wi-Fi)
    └── settings.html        # Paramètres (apparence, SMTP, version, compte)
```

---

## Sécurité

- **HTTPS natif** — certificat auto-signé, tout le trafic chiffré, port 443
- Mots de passe hachés avec **bcrypt**
- Protection **brute-force** : 5 tentatives, blocage 5 minutes
- Tokens **CSRF** sur tous les formulaires
- Sessions signées avec une clé secrète auto-générée
- Codes de reset à usage unique, expiry 15 minutes
- Isolation complète des données par utilisateur
- Fichiers sensibles exclus du dépôt : `.env`, `users.db`, `ssl/`

---

## API Omada supportée

| Section | Opérations |
|---------|-----------|
| **Clients MSP** | Lister, créer, supprimer (unitaire et en masse) |
| **Sites** | Lister, créer, supprimer, détail, forget devices, export |
| **Devices** | Lister, forget, adopt |
| **Clients réseau** | Lister par site |
| **WAN** | Statut ports, configuration |
| **WireGuard VPN** | Lister, modifier, supprimer |
| **Wi-Fi SSID** | Lister par WLAN, activer/désactiver, modifier |

---

## Changelog

### v1.1.0 (2026-04-02)

**Nouvelles fonctionnalités :**
- Mode Standard (non-MSP) — connexion directe aux contrôleurs sans passer par la vue clients
- Authorization Code OAuth — support complet du flow en 3 étapes pour créer/supprimer des clients MSP
- Deux applications OpenAPI séparées : Client Credentials (opérations courantes) + Authorization Code (CRUD clients)
- Recherche, tri et filtrage des clients — barre d'outils avec recherche instantanée, tri par nom/sites/API
- Vue tableau des clients — basculer entre cartes et tableau compact
- Sélection et suppression en masse des clients
- Forget devices en masse sur les sites sélectionnés
- Adoption de devices par MAC
- Export des devices en CSV
- Pagination automatique — récupération de tous les clients et sites sans limite
- Refactoring en modules (config.py, db.py, blueprints/auth.py)

### v1.0.4

- Fix: vérification de version considère current >= latest comme à jour

### v1.0.3

- Dark mode, redesign navbar, fix logout isolation

### v1.0.2

- Mise à jour depuis l'interface, fix pip3 sur Python managé

### v1.0.1

- Password reset avec vérification SMTP optionnelle

### v1.0.0

- Release initiale : multi-utilisateurs, multi-contrôleurs, HTTPS natif, PWA

---

## Licence

MIT © 2025–2026 YakuMawi
