# 🔐 CertificationManager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

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
│   ├── core/              # Logique métier principale
│   │   ├── certificate/   # Gestion des certificats
│   │   ├── key/          # Gestion des clés
│   │   ├── storage/      # Stockage sécurisé
│   │   └── validation/   # Validation des certificats
│   ├── cli/              # Interface en ligne de commande
│   ├── api/              # API REST (Phase 3)
│   ├── web/              # Interface web (Phase 3)
│   └── utils/            # Utilitaires
├── tests/                # Tests unitaires et d'intégration
├── docs/                 # Documentation
├── config/               # Fichiers de configuration
└── requirements.txt      # Dépendances Python
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

- Stockage sécurisé des clés privées (chiffrement)
- Validation stricte des entrées
- Pas de stockage de mots de passe en clair
- Audit et journalisation des opérations sensibles

## 📚 Documentation

- [Documentation complète](docs/README.md)
- [Guide de développement](docs/DEVELOPMENT.md)
- [Guide d'API](docs/API.md)

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

![GitHub issues](https://img.shields.io/github/issues/natrasta2dev/CertificationManager)
![GitHub pull requests](https://img.shields.io/github/issues-pr/natrasta2dev/CertificationManager)
![GitHub stars](https://img.shields.io/github/stars/natrasta2dev/CertificationManager?style=social)

---

⭐ Si ce projet vous est utile, n'hésitez pas à lui donner une étoile !

