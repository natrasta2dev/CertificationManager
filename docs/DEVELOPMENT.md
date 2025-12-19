# 🛠️ Guide de développement - CertificationManager

Ce guide est destiné aux développeurs souhaitant contribuer au projet ou comprendre son fonctionnement interne.

## 📋 Table des matières

- [Environnement de développement](#environnement-de-développement)
- [Structure du code](#structure-du-code)
- [Commandes CLI](#commandes-cli)
- [Tests](#tests)
- [Standards de code](#standards-de-code)
- [Workflow de contribution](#workflow-de-contribution)

## Environnement de développement

### Configuration initiale

```bash
# Cloner le dépôt
git clone https://github.com/natrasta2dev/CertificationManager.git
cd CertificationManager

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate

# Installer les dépendances de développement
pip install -r requirements-dev.txt
pip install -r requirements.txt

# Installer en mode développement
pip install -e .
```

### Outils de développement

- **pytest** : Framework de tests
- **black** : Formateur de code
- **flake8** : Linter
- **mypy** : Vérification de types (optionnel)

## Structure du code

### Modules Core

#### `src/core/certificate/__init__.py`
Gestionnaire principal des certificats.

**Classes principales :**
- `CertificateManager` : Génération de certificats auto-signés et CSR

**Méthodes principales :**
- `generate_self_signed_cert()` : Génère un certificat auto-signé
- `generate_csr()` : Génère une Certificate Signing Request

#### `src/core/certificate/client.py`
Gestion des certificats client pour mTLS.

**Classes principales :**
- `ClientCertificateManager` : Génération de certificats client

**Méthodes principales :**
- `generate_client_cert()` : Génère un certificat client
- `export_for_browser()` : Exporte en PKCS#12 pour navigateur

#### `src/core/key.py`
Génération de clés cryptographiques.

**Classes principales :**
- `KeyManager` : Gestionnaire de clés

**Méthodes principales :**
- `generate_rsa_key()` : Génère une clé RSA
- `generate_ecdsa_key()` : Génère une clé ECDSA

#### `src/core/storage.py`
Stockage sécurisé des certificats et clés.

**Classes principales :**
- `SecureStorage` : Gestionnaire de stockage

**Méthodes principales :**
- `save_certificate()` : Sauvegarde un certificat
- `save_key()` : Sauvegarde une clé privée
- `list_certificates()` : Liste tous les certificats
- `get_certificate()` : Récupère un certificat

#### `src/core/validation/`
Modules de validation.

**Classes principales :**
- `CertificateValidator` : Validation de certificats
- `DomainValidator` : Validation de domaines (support wildcard)

### Interface CLI

#### `src/cli/commands.py`
Commandes en ligne de commande.

**Commandes principales :**
- `certmanager generate` : Génère un certificat
- `certmanager csr` : Génère une CSR
- `certmanager list` : Liste les certificats
- `certmanager info` : Affiche les détails d'un certificat
- `certmanager verify` : Vérifie un certificat
- `certmanager delete` : Supprime un certificat
- `certmanager import` : Importe un certificat
- `certmanager export` : Exporte un certificat
- `certmanager renew` : Renouvelle un certificat
- `certmanager ca` : Gère les CA
- `certmanager letsencrypt` : Gère Let's Encrypt
- `certmanager client` : Gère les certificats client
- `certmanager web` : Lance l'interface web

## Commandes CLI

### Génération de certificats

```bash
# Certificat auto-signé simple
certmanager generate --common-name "example.com"

# Avec options complètes
certmanager generate \
  --common-name "example.com" \
  --validity-days 365 \
  --key-type RSA \
  --key-size 2048 \
  --country FR \
  --organization "My Company" \
  --san-dns "www.example.com" \
  --san-dns "api.example.com"

# Certificat wildcard
certmanager generate --common-name "*.example.com"
```

### Génération de CSR

```bash
certmanager csr \
  --common-name "example.com" \
  --organization "My Company" \
  --san-dns "www.example.com"
```

### Gestion des certificats

```bash
# Lister tous les certificats
certmanager list

# Détails d'un certificat
certmanager info --certificate-id <id>

# Vérifier un certificat
certmanager verify --certificate-id <id>

# Renouveler un certificat
certmanager renew --certificate-id <id>

# Supprimer un certificat
certmanager delete --certificate-id <id>
```

### Import/Export

```bash
# Importer un certificat
certmanager import --file cert.pem

# Importer depuis PKCS#12
certmanager import --file cert.p12 --password "secret"

# Exporter un certificat
certmanager export --certificate-id <id> --format PEM

# Exporter en PKCS#12
certmanager export --certificate-id <id> --format PKCS12 --password "secret"
```

### Gestion des CA

```bash
# Lister les CA
certmanager ca list

# Importer une CA
certmanager ca import --file ca.pem

# Créer une CA racine
certmanager ca create-root --common-name "My Root CA"
```

### Let's Encrypt

```bash
# Obtenir un certificat
certmanager letsencrypt obtain \
  --domain example.com \
  --email admin@example.com

# Renouveler un certificat
certmanager letsencrypt renew --certificate-id <id>

# Renouveler tous les certificats
certmanager letsencrypt renew-all
```

### Certificats client (mTLS)

```bash
# Générer un certificat client
certmanager client generate \
  --common-name "client.example.com" \
  --validity-days 365

# Signer par une CA
certmanager client generate \
  --common-name "client.example.com" \
  --ca-id <ca_id> \
  --password "secret"

# Exporter pour navigateur
certmanager client export --certificate-id <id> --password "secret"
```

## Tests

### Lancer les tests

```bash
# Tous les tests
pytest

# Tests unitaires uniquement
pytest tests/unit/

# Tests d'intégration
pytest tests/integration/

# Avec couverture
pytest --cov=src --cov-report=html

# Tests spécifiques
pytest tests/unit/test_certificate.py
```

### Structure des tests

```
tests/
├── unit/              # Tests unitaires
│   ├── test_certificate.py
│   ├── test_key.py
│   └── test_validation.py
└── integration/      # Tests d'intégration
```

### Écrire des tests

Exemple de test unitaire :

```python
import pytest
from src.core.certificate import CertificateManager

def test_generate_self_signed_cert():
    manager = CertificateManager()
    cert, key, metadata = manager.generate_self_signed_cert(
        common_name="test.example.com",
        validity_days=365
    )
    
    assert cert is not None
    assert key is not None
    assert metadata["common_name"] == "test.example.com"
```

## Standards de code

### Formatage

Le projet utilise **black** pour le formatage automatique :

```bash
# Formater tout le code
black src/ tests/

# Vérifier sans modifier
black --check src/ tests/
```

### Linting

Le projet utilise **flake8** pour le linting :

```bash
# Linter le code
flake8 src/ tests/
```

### Types

Le projet utilise des annotations de type. Exemple :

```python
from typing import Optional, List, Tuple
from cryptography import x509

def generate_cert(
    common_name: str,
    validity_days: int = 365,
    san_dns: Optional[List[str]] = None
) -> Tuple[x509.Certificate, bytes, dict]:
    ...
```

## Workflow de contribution

### 1. Fork et clone

```bash
# Fork le projet sur GitHub, puis
git clone https://github.com/VOTRE_USERNAME/CertificationManager.git
cd CertificationManager
```

### 2. Créer une branche

```bash
git checkout -b feature/ma-nouvelle-fonctionnalite
```

### 3. Développer

- Écrire le code
- Ajouter des tests
- Vérifier avec `black` et `flake8`
- Lancer les tests

### 4. Commit

Utiliser les [conventional commits](https://www.conventionalcommits.org/) :

```bash
git commit -m "feat: add new feature"
git commit -m "fix: correct bug in validation"
git commit -m "docs: update README"
```

### 5. Push et Pull Request

```bash
git push origin feature/ma-nouvelle-fonctionnalite
```

Puis ouvrir une Pull Request sur GitHub.

### Types de commits

- `feat:` : Nouvelle fonctionnalité
- `fix:` : Correction de bug
- `docs:` : Documentation
- `style:` : Formatage
- `refactor:` : Refactorisation
- `test:` : Tests
- `chore:` : Tâches de maintenance

## Ressources

- [Documentation complète](README.md)
- [Guide d'API](API.md)
- [ROADMAP.md](../ROADMAP.md)
- [TODO.md](../TODO.md)

