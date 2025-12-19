# 🚀 Guide de démarrage rapide

Ce guide vous permet de démarrer rapidement avec CertificationManager.

## Installation

```bash
# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Installer en mode développement
pip install -e .
```

## Premiers pas

### 1. Générer un certificat auto-signé

```bash
certmanager generate --common-name "example.com" --validity-days 365
```

### 2. Lister les certificats

```bash
certmanager list
```

### 3. Voir les détails d'un certificat

```bash
# Par ID (après avoir listé)
certmanager info --id <certificate-id>

# Depuis un fichier
certmanager info --certificate cert.pem
```

### 4. Vérifier un certificat

```bash
certmanager verify --id <certificate-id>
```

### 5. Générer une CSR

```bash
certmanager csr --common-name "example.com" --organization "My Company"
```

## Exemples avancés

### Certificat avec détails complets

```bash
certmanager generate \
  --common-name "example.com" \
  --country "FR" \
  --state "Ile-de-France" \
  --locality "Paris" \
  --organization "My Company" \
  --organizational-unit "IT Department" \
  --email "admin@example.com" \
  --san-dns "www.example.com" \
  --san-dns "api.example.com" \
  --validity-days 730 \
  --key-size 4096
```

### Certificat ECDSA

```bash
certmanager generate \
  --common-name "example.com" \
  --key-type ECDSA \
  --validity-days 365
```

### Sauvegarder dans un fichier

```bash
certmanager generate \
  --common-name "example.com" \
  --output /path/to/certificate.pem
```

## Tests

```bash
# Lancer tous les tests
pytest

# Avec couverture
pytest --cov=src --cov-report=html
```

## Structure des fichiers

Les certificats sont stockés dans `~/.certmanager/` :
- `certificates/` : Certificats PEM
- `keys/` : Clés privées (permissions 600)
- `csr/` : Certificate Signing Requests
- `metadata.json` : Métadonnées

## Aide

```bash
# Aide générale
certmanager --help

# Aide pour une commande
certmanager generate --help
```

