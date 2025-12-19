# 📖 Guide de démarrage - CertificationManager

Ce guide vous explique comment créer et développer ce projet de gestion de certificats cryptographiques.

## 🎯 Vue d'ensemble

**CertificationManager** est une application système permettant de :
- Générer des certificats X.509 (auto-signés et CSR)
- Stocker et gérer des certificats de manière sécurisée
- Valider et vérifier les certificats
- Gérer le cycle de vie des certificats (expiration, renouvellement)

## 🛠️ Comment créer ce projet

### Étape 1 : Choix des technologies

#### Langage de programmation
- **Python 3.9+** : Langage principal
  - Raison : Excellentes bibliothèques cryptographiques (cryptography, pyOpenSSL)
  - Facile à utiliser et maintenir
  - Large communauté open source

#### Bibliothèques principales
- **cryptography** : Bibliothèque cryptographique moderne et sécurisée
- **pyOpenSSL** : Interface Python pour OpenSSL
- **Click** : Framework pour créer des interfaces CLI élégantes

#### Architecture
- **Structure modulaire** : Séparation des responsabilités
- **CLI d'abord** : Interface en ligne de commande pour commencer
- **API REST ensuite** : Pour l'intégration (Phase 3)
- **Interface web** : Dashboard pour la gestion visuelle (Phase 3)

### Étape 2 : Structure du projet

```
CertificationManager/
├── src/
│   ├── core/              # Logique métier
│   │   ├── __init__.py
│   │   ├── certificate.py    # Gestion des certificats
│   │   ├── key.py             # Gestion des clés
│   │   ├── storage.py         # Stockage sécurisé
│   │   └── validation.py      # Validation
│   ├── cli/               # Interface ligne de commande
│   │   ├── __init__.py
│   │   └── commands.py
│   └── utils/             # Utilitaires
│       ├── __init__.py
│       └── helpers.py
├── tests/                 # Tests
├── docs/                  # Documentation
├── config/                # Configuration
├── README.md
├── ROADMAP.md
├── requirements.txt
└── .gitignore
```

### Étape 3 : Développement par phases

#### Phase 1 - MVP (4 semaines)

**Semaine 1 : Infrastructure**
1. Créer la structure de répertoires
2. Configurer l'environnement Python (venv)
3. Installer les dépendances (cryptography, click)
4. Configurer les outils de développement (pytest, black, flake8)
5. Créer les fichiers de base (setup.py, requirements.txt)

**Semaine 2 : Génération de certificats**
1. Implémenter la génération de clés RSA/ECDSA
2. Implémenter la génération de certificats auto-signés
3. Implémenter la génération de CSR
4. Tester chaque fonctionnalité

**Semaine 3 : Stockage**
1. Créer le système de stockage local
2. Implémenter le chiffrement des clés privées
3. Créer le système de métadonnées
4. Implémenter la recherche et l'indexation

**Semaine 4 : CLI et validation**
1. Créer l'interface CLI avec Click
2. Implémenter les commandes de base (generate, list, info, verify)
3. Implémenter la validation de certificats
4. Tester l'intégration complète

#### Phase 2 - Gestion (4 semaines)

**Semaine 5-6 : Cycle de vie**
- Suivi des dates d'expiration
- Système d'alertes
- Renouvellement manuel

**Semaine 7-8 : Import/Export**
- Import depuis différents formats
- Export vers différents formats
- Gestion des CA

#### Phase 3 - Interface (4 semaines)

**Semaine 9-10 : API REST**
- Framework web (Flask ou FastAPI)
- Endpoints REST
- Documentation API

**Semaine 11-12 : Interface web**
- Dashboard
- Authentification
- Intégrations

### Étape 4 : Implémentation technique

#### Génération de certificats

```python
# Exemple de structure pour src/core/certificate.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_self_signed_cert(
    common_name: str,
    validity_days: int = 365,
    key_size: int = 2048
):
    # Générer clé privée
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    # Créer le certificat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=validity_days)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return cert, private_key
```

#### Stockage sécurisé

```python
# Exemple pour src/core/storage.py
import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

class SecureStorage:
    def __init__(self, storage_path: str = "~/.certmanager"):
        self.storage_path = Path(storage_path).expanduser()
        self.certs_dir = self.storage_path / "certificates"
        self.keys_dir = self.storage_path / "keys"
        self.metadata_file = self.storage_path / "metadata.json"
        
        # Créer les répertoires
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Permissions sécurisées (chmod 700)
        os.chmod(self.storage_path, 0o700)
        os.chmod(self.keys_dir, 0o700)
    
    def save_certificate(self, cert, private_key, metadata):
        # Sauvegarder le certificat
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_file = self.certs_dir / f"{metadata['id']}.pem"
        cert_file.write_bytes(cert_pem)
        
        # Sauvegarder la clé privée (chiffrée)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_file = self.keys_dir / f"{metadata['id']}.key"
        key_file.write_bytes(key_pem)
        os.chmod(key_file, 0o600)  # Permissions restrictives
        
        # Sauvegarder les métadonnées
        self._update_metadata(metadata)
```

#### Interface CLI

```python
# Exemple pour src/cli/commands.py
import click
from src.core.certificate import generate_self_signed_cert
from src.core.storage import SecureStorage

@click.group()
def cli():
    """CertificationManager - Gestionnaire de certificats"""
    pass

@cli.command()
@click.option('--common-name', '-n', required=True, help='Nom commun (CN)')
@click.option('--validity-days', '-d', default=365, help='Jours de validité')
@click.option('--key-size', '-s', default=2048, help='Taille de la clé')
def generate(common_name, validity_days, key_size):
    """Génère un certificat auto-signé"""
    cert, private_key = generate_self_signed_cert(
        common_name, validity_days, key_size
    )
    storage = SecureStorage()
    metadata = {
        'id': str(uuid.uuid4()),
        'common_name': common_name,
        'created': datetime.now().isoformat(),
        'validity_days': validity_days
    }
    storage.save_certificate(cert, private_key, metadata)
    click.echo(f"✅ Certificat généré: {common_name}")

@cli.command()
def list():
    """Liste tous les certificats"""
    storage = SecureStorage()
    certs = storage.list_certificates()
    for cert in certs:
        click.echo(f"  - {cert['common_name']} (expire: {cert['expires']})")

if __name__ == '__main__':
    cli()
```

### Étape 5 : Tests

```python
# Exemple pour tests/test_certificate.py
import pytest
from src.core.certificate import generate_self_signed_cert
from datetime import datetime, timedelta

def test_generate_self_signed_cert():
    cert, private_key = generate_self_signed_cert(
        "test.example.com",
        validity_days=365
    )
    
    assert cert is not None
    assert private_key is not None
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test.example.com"
    
    # Vérifier la validité
    assert cert.not_valid_before <= datetime.utcnow()
    assert cert.not_valid_after >= datetime.utcnow() + timedelta(days=364)
```

### Étape 6 : Déploiement sur GitHub

1. **Créer le dépôt GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/votre-username/CertificationManager.git
   git push -u origin main
   ```

2. **Configurer GitHub**
   - Ajouter une description
   - Ajouter des topics (cryptography, certificates, python, security)
   - Configurer les badges dans le README
   - Activer GitHub Actions pour les tests (optionnel)

3. **Créer les releases**
   - Taguer les versions (v0.1.0, v0.2.0, etc.)
   - Créer des releases avec des notes de version

## 📚 Ressources et documentation

### Documentation à consulter
- [cryptography.io documentation](https://cryptography.io/)
- [X.509 Certificate Standards](https://tools.ietf.org/html/rfc5280)
- [Click Documentation](https://click.palletsprojects.com/)

### Concepts cryptographiques importants
- **X.509** : Standard pour les certificats
- **PKI (Public Key Infrastructure)** : Infrastructure à clés publiques
- **CSR (Certificate Signing Request)** : Demande de signature de certificat
- **CA (Certificate Authority)** : Autorité de certification
- **SAN (Subject Alternative Name)** : Noms alternatifs dans un certificat

## ✅ Checklist de démarrage

- [ ] Créer la structure de répertoires
- [ ] Configurer l'environnement Python
- [ ] Installer les dépendances
- [ ] Créer le premier module (génération de clés)
- [ ] Écrire les premiers tests
- [ ] Implémenter la génération de certificats
- [ ] Créer l'interface CLI de base
- [ ] Tester l'intégration complète
- [ ] Créer le dépôt GitHub
- [ ] Publier le code

## 🎓 Apprentissage progressif

1. **Commencer simple** : Un certificat auto-signé basique
2. **Ajouter progressivement** : CSR, validation, stockage
3. **Itérer** : Améliorer basé sur les retours
4. **Documenter** : À chaque étape

## 🚨 Points d'attention

### Sécurité
- ⚠️ **NE JAMAIS** commiter des clés privées ou certificats
- ⚠️ Toujours chiffrer les clés privées stockées
- ⚠️ Utiliser des permissions restrictives (chmod 600)
- ⚠️ Valider toutes les entrées utilisateur

### Bonnes pratiques
- Écrire des tests pour chaque fonctionnalité
- Documenter le code
- Suivre les conventions Python (PEP 8)
- Gérer les erreurs proprement

---

**Bon développement ! 🚀**

