# 🔐 CertificationManager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![CI](https://github.com/natrasta2dev/CertificationManager/actions/workflows/ci.yml/badge.svg)](https://github.com/natrasta2dev/CertificationManager/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-133-green.svg)](/)
[![Coverage](https://img.shields.io/badge/coverage-61%25-green.svg)](/)
[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](/)

**CertificationManager** est une application système open source de gestion de certificats cryptographiques, permettant de créer, stocker, valider et gérer des certificats X.509 de manière sécurisée.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Contribution](#-contribution)
- [Sécurité](#-sécurité)
- [License](#-license)


## 🏗️ Architecture

```
CertificationManager/
├── src/
│   ├── config/            # Configuration (.env)
│   ├── core/              # Logique métier (certificats, auth, stockage…)
│   │   ├── certificate/   # Gestion des certificats
│   │   └── validation/    # Validation des certificats
│   ├── cli/               # Interface en ligne de commande
│   └── web/               # API REST + interface web
│       └── routers/       # Routes FastAPI par domaine
├── config/                # .env.example
├── tests/                 # Tests unitaires et d'intégration
├── docs/                  # Documentation
├── Dockerfile             # Image Docker
└── docker-compose.yml     # Déploiement containerisé
```

## 🚀 Installation

### Prérequis

- Python 3.9 ou supérieur
- pip (gestionnaire de paquets Python)
- OpenSSL (pour certaines opérations)

### Installation depuis les sources

```bash
# Cloner le dépôt
git clone https://github.com/natrasta2dev/CertificationManager.git
cd CertificationManager

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Installer en mode développement
pip install -e .
```

## 💻 Utilisation

### Interface Web (Recommandé)

Lancez l'interface web moderne et intuitive :

```bash
# Activer l'environnement virtuel
source venv/bin/activate

# Lancer l'interface web
certmanager web

# Ou avec des options personnalisées
certmanager web --host 0.0.0.0 --port 8080
```

L'interface sera accessible sur `http://127.0.0.1:8000` par défaut.

### Docker

```bash
docker compose up --build
# ou
make docker-run
```

### Authentification (production)

```bash
export CERTMANAGER_AUTH_ENABLED=true
export CERTMANAGER_ADMIN_PASSWORD="votre-mot-de-passe-securise"
export CERTMANAGER_JWT_SECRET="cle-secrete-de-32-octets-minimum"
certmanager web
```

Chiffrement des clés privées :

```bash
export CERTMANAGER_ENCRYPT_KEYS=true
export CERTMANAGER_STORAGE_PASSWORD="mot-de-passe-stockage"
```

HTTPS :

```bash
certmanager web --ssl-certfile cert.pem --ssl-keyfile key.pem --host 0.0.0.0
```

Gestion utilisateurs CLI :

```bash
certmanager user create -u alice --role operator
certmanager user list
```

Connexion web : `http://127.0.0.1:8000/api/login` — utilisateur par défaut `admin`.

### CLI - Exemples de base

```bash
# Générer un certificat auto-signé
certmanager generate --common-name "example.com" --validity-days 365

# Générer une CSR
certmanager csr --common-name "example.com" --key-size 2048

# Lister tous les certificats
certmanager list

# Vérifier un certificat
certmanager verify --certificate cert.pem

# Voir les détails d'un certificat
certmanager info --certificate cert.pem
```

### PKI locale (CA)

```bash
# Générer une CA racine
certmanager ca generate -n "ca-root.local" --organization "ACME"

# Générer une CA intermédiaire
certmanager ca generate -n "intermediate.local" --intermediate --parent-id <ROOT_CA_ID>

# Signer un certificat serveur
certmanager ca sign --ca-id <CA_ID> -n "app.example.com"

# Signer une CSR stockée
certmanager ca sign --ca-id <CA_ID> --csr-id <CSR_ID>
```

API : `POST /api/ca/generate`, `POST /api/ca/{id}/sign`, `POST /api/ca/{id}/sign-csr`

### Backup & renouvellement

```bash
# Sauvegarde (chiffrement optionnel)
certmanager backup -o backup.tar.gz
certmanager backup -o backup.enc -p "mot-de-passe"

# Restauration
certmanager restore -i backup.tar.gz --yes

# Renouveler tous les certificats expirant sous 30 jours
certmanager renew --all --days 30
certmanager renew --all --dry-run

# Gestion CSR
certmanager csr generate -n "app.example.com"
certmanager csr list
certmanager csr delete --id <CSR_ID>
```

### Automatisation (scheduler, email, webhooks)

```bash
# Exécuter une tâche (compatible cron)
certmanager scheduler run check-alerts
certmanager scheduler run auto-renew --days 30
certmanager scheduler run compliance-scan

# Boucle planifiée (premier plan)
certmanager scheduler start --interval 60

# Configuration
certmanager scheduler config --enable-auto-renew --renew-days 30
certmanager scheduler status
```

Variables SMTP (ou fichier `config/notifications.json`) :
```bash
export CERTMANAGER_SMTP_ENABLED=true
export CERTMANAGER_SMTP_HOST=smtp.example.com
export CERTMANAGER_SMTP_TO=admin@example.com
```

API : `GET/PUT /api/notifications/config`, `GET/PUT /api/webhooks/config`, `GET /api/scheduler/status`, `POST /api/scheduler/run/{job}`

## 🤝 Contribution

Les contributions sont les bienvenues ! Veuillez lire [CONTRIBUTING.md](CONTRIBUTING.md) pour les détails sur notre code de conduite et le processus de soumission de pull requests.

### Comment contribuer

1. Fork le projet
2. Créer une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 🔒 Sécurité

La sécurité est une priorité absolue. Veuillez consulter [SECURITY.md](SECURITY.md) pour les directives de signalement des vulnérabilités.

### Bonnes pratiques implémentées

- Auth JWT optionnelle avec rôles (admin / operator / viewer)
- Mots de passe hashés bcrypt (jamais en clair)
- Rate limiting API configurable
- Permissions fichiers restrictives (600)
- Métadonnées écrites de façon atomique
- CORS configurable

## 📚 Documentation

- [Documentation complète](docs/README.md)
- [Guide de développement](docs/DEVELOPMENT.md)
- [Guide d'API](docs/API.md)
- [Déploiement production](docs/DEPLOYMENT.md)
- [Changelog](CHANGELOG.md)
- [Sécurité](SECURITY.md)
- [Roadmap v2](TODO-V2.md)

## 🧪 Tests

```bash
# Lancer tous les tests
pytest

# Avec couverture de code
pytest --cov=src --cov-report=html
```

## 📝 License

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Auteurs

- **natrasta2dev** - *Créateur initial* - [natrasta2dev](https://github.com/natrasta2dev)

## 🙏 Remerciements

- Cryptography.io pour la bibliothèque Python
- OpenSSL pour les outils cryptographiques
- La communauté open source

## 📊 Statut du projet

**Version** : 0.2.0 — Production-ready (auth, PKI, automatisation, web v2)

- ✅ 133 tests automatisés (~61 % couverture)
- ✅ CI GitHub Actions (seuil couverture 60 %)
- ✅ Docker / docker-compose
- ✅ Auth JWT, audit, backup, scheduler, conformité
- ✅ Interface web : pagination, archives, CSR, paramètres, mode sombre

Roadmap détaillée : [TODO-V2.md](TODO-V2.md) · Historique : [CHANGELOG.md](CHANGELOG.md)

---

⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !

