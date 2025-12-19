# 📚 Documentation complète - CertificationManager

Bienvenue dans la documentation complète de CertificationManager, votre solution open source pour la gestion de certificats cryptographiques X.509.

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Configuration](#configuration)
- [Sécurité](#sécurité)
- [Dépannage](#dépannage)

## Vue d'ensemble

CertificationManager est une application système complète permettant de :

- ✅ Générer des certificats auto-signés et des CSR
- ✅ Gérer le cycle de vie des certificats
- ✅ Importer et exporter des certificats
- ✅ Gérer les autorités de certification (CA)
- ✅ Intégrer Let's Encrypt pour l'obtention automatique de certificats
- ✅ Gérer les certificats wildcard et client (mTLS)
- ✅ Interface web moderne avec dashboard et graphiques
- ✅ API REST complète

## Architecture

### Structure du projet

```
CertificationManager/
├── src/
│   ├── core/                    # Logique métier principale
│   │   ├── certificate/        # Gestion des certificats
│   │   │   ├── __init__.py     # CertificateManager
│   │   │   └── client.py       # ClientCertificateManager
│   │   ├── key.py              # Génération de clés
│   │   ├── storage.py          # Stockage sécurisé
│   │   ├── validation/         # Validation des certificats
│   │   │   ├── certificate.py  # CertificateValidator
│   │   │   └── domain.py        # DomainValidator
│   │   ├── lifecycle.py        # Cycle de vie
│   │   ├── alerts.py            # Système d'alertes
│   │   ├── renewal.py          # Renouvellement
│   │   ├── import_export.py     # Import/Export
│   │   ├── ca_manager.py        # Gestion des CA
│   │   └── letsencrypt.py       # Intégration Let's Encrypt
│   ├── cli/                     # Interface ligne de commande
│   │   ├── commands.py         # Commandes CLI
│   │   └── web_command.py      # Commande web
│   └── web/                     # Interface web
│       ├── app.py              # Application FastAPI
│       ├── static/             # Fichiers statiques
│       └── templates/          # Templates HTML
├── tests/                       # Tests unitaires et d'intégration
├── docs/                        # Documentation
└── config/                      # Fichiers de configuration
```

### Composants principaux

#### Core Modules

- **CertificateManager** : Génération et gestion des certificats
- **ClientCertificateManager** : Gestion des certificats client (mTLS)
- **KeyManager** : Génération de clés RSA et ECDSA
- **SecureStorage** : Stockage sécurisé avec permissions
- **CertificateValidator** : Validation des certificats
- **DomainValidator** : Validation des noms de domaine (wildcard support)
- **CertificateLifecycle** : Suivi du cycle de vie
- **AlertManager** : Système d'alertes d'expiration
- **CertificateRenewal** : Renouvellement de certificats
- **CertificateImporter/Exporter** : Import/Export multi-formats
- **CAManager** : Gestion des autorités de certification
- **LetsEncryptManager** : Intégration ACME via Certbot

## Installation

### Prérequis

- Python 3.9 ou supérieur
- pip (gestionnaire de paquets Python)
- OpenSSL (pour certaines opérations)
- Certbot (pour Let's Encrypt, optionnel)

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

### Vérification de l'installation

```bash
# Vérifier que la commande est disponible
certmanager --help

# Vérifier la version
certmanager --version
```

## Utilisation

### Interface Web

L'interface web est la méthode recommandée pour utiliser CertificationManager :

```bash
# Lancer l'interface web
certmanager web

# Avec options personnalisées
certmanager web --host 0.0.0.0 --port 8080
```

L'interface sera accessible sur `http://127.0.0.1:8000` par défaut.

### Interface CLI

Voir [Guide de développement](DEVELOPMENT.md) pour les détails complets.

### API REST

Voir [Guide d'API](API.md) pour la documentation complète de l'API.

## Configuration

### Variables d'environnement

Le projet utilise des chemins par défaut pour le stockage :

- Certificats : `./storage/certificates/`
- Clés : `./storage/keys/`
- CA : `./storage/ca/`
- Métadonnées : `./storage/metadata/`

### Permissions

Les fichiers sont automatiquement créés avec les permissions appropriées :
- Clés privées : `600` (rw-------)
- Répertoires : `700` (rwx------)

## Sécurité

### Bonnes pratiques implémentées

- ✅ Stockage sécurisé des clés privées
- ✅ Validation stricte des entrées
- ✅ Pas de stockage de mots de passe en clair
- ✅ Audit et journalisation des opérations sensibles
- ✅ Support du chiffrement des clés privées
- ✅ Validation des domaines (wildcard support)

### Recommandations

1. Ne jamais commiter les clés privées ou certificats
2. Utiliser des mots de passe forts pour les PKCS#12
3. Sauvegarder régulièrement le répertoire `storage/`
4. Surveiller les alertes d'expiration
5. Utiliser HTTPS pour l'interface web en production

## Dépannage

### Problèmes courants

#### Erreur de permissions

```bash
# Vérifier les permissions du répertoire storage
ls -la storage/

# Corriger les permissions si nécessaire
chmod 700 storage/
chmod 600 storage/keys/*
```

#### Certbot non trouvé

```bash
# Installer Certbot
# Sur Ubuntu/Debian
sudo apt-get install certbot

# Sur macOS
brew install certbot
```

#### Port déjà utilisé

```bash
# Utiliser un autre port
certmanager web --port 8080
```

## Ressources supplémentaires

- [Guide de développement](DEVELOPMENT.md)
- [Guide d'API](API.md)

## Support

Pour signaler un bug ou proposer une fonctionnalité, veuillez ouvrir une issue sur [GitHub](https://github.com/natrasta2dev/CertificationManager/issues).

