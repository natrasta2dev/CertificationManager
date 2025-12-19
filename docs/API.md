# 🔌 Guide d'API - CertificationManager

Documentation complète de l'API REST de CertificationManager.

## 📋 Table des matières

- [Base URL](#base-url)
- [Authentification](#authentification)
- [Format des réponses](#format-des-réponses)
- [Endpoints](#endpoints)
  - [Statistiques](#statistiques)
  - [Alertes](#alertes)
  - [Certificats](#certificats)
  - [CSR](#csr)
  - [Import/Export](#importexport)
  - [Renouvellement](#renouvellement)
  - [CA (Autorités de certification)](#ca-autorités-de-certification)
  - [Let's Encrypt](#lets-encrypt)
  - [Certificats client](#certificats-client)

## Base URL

Par défaut, l'API est accessible à :
```
http://127.0.0.1:8000/api
```

## Authentification

Actuellement, l'API ne nécessite pas d'authentification. Cette fonctionnalité sera ajoutée dans une version future.

## Format des réponses

### Succès

```json
{
  "success": true,
  "data": { ... }
}
```

### Erreur

```json
{
  "success": false,
  "error": "Message d'erreur"
}
```

## Endpoints

### Statistiques

#### GET `/api/statistics`

Récupère les statistiques globales des certificats.

**Réponse :**
```json
{
  "success": true,
  "data": {
    "total": 10,
    "valid": 8,
    "expired": 2,
    "expiring_soon": 1,
    "by_key_type": {
      "RSA": 7,
      "ECDSA": 3
    }
  }
}
```

### Alertes

#### GET `/api/alerts`

Récupère toutes les alertes.

**Paramètres de requête :**
- `include_expired` (bool, optionnel) : Inclure les certificats expirés (défaut: true)

**Réponse :**
```json
{
  "success": true,
  "data": [
    {
      "certificate_id": "...",
      "level": "warning",
      "message": "Le certificat expire dans 15 jours",
      "days_until_expiry": 15
    }
  ]
}
```

#### GET `/api/alerts/{cert_id}`

Récupère les alertes pour un certificat spécifique.

### Certificats

#### GET `/api/certificates`

Liste tous les certificats.

**Paramètres de requête :**
- `include_expired` (bool, optionnel) : Inclure les certificats expirés

**Réponse :**
```json
{
  "success": true,
  "data": [
    {
      "id": "...",
      "common_name": "example.com",
      "is_expired": false,
      "days_until_expiry": 45,
      "not_valid_after": "2024-12-31T23:59:59",
      "key_type": "RSA",
      "key_size": 2048,
      "is_wildcard": false,
      "is_client": false
    }
  ]
}
```

#### GET `/api/certificates/expiring`

Récupère les certificats expirant bientôt.

**Paramètres de requête :**
- `days` (int, optionnel) : Nombre de jours (défaut: 30)

#### POST `/api/certificates`

Crée un nouveau certificat auto-signé.

**Corps de la requête :**
```json
{
  "common_name": "example.com",
  "validity_days": 365,
  "key_type": "RSA",
  "key_size": 2048,
  "country": "FR",
  "organization": "My Company",
  "san_dns": ["www.example.com", "api.example.com"]
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "common_name": "example.com",
    "message": "Certificat créé avec succès"
  }
}
```

#### GET `/api/certificates/{cert_id}`

Récupère les détails d'un certificat.

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "common_name": "example.com",
    "subject": { ... },
    "issuer": { ... },
    "not_valid_before": "...",
    "not_valid_after": "...",
    "is_expired": false,
    "days_until_expiry": 45,
    "key_type": "RSA",
    "key_size": 2048
  }
}
```

#### GET `/api/certificates/{cert_id}/verify`

Vérifie un certificat.

**Réponse :**
```json
{
  "success": true,
  "data": {
    "is_valid": true,
    "errors": []
  }
}
```

#### GET `/api/certificates/status/{cert_id}`

Récupère le statut d'un certificat.

#### DELETE `/api/certificates/{cert_id}`

Supprime un certificat.

### CSR

#### POST `/api/csr`

Crée une Certificate Signing Request.

**Corps de la requête :**
```json
{
  "common_name": "example.com",
  "key_type": "RSA",
  "key_size": 2048,
  "organization": "My Company",
  "san_dns": ["www.example.com"]
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
    "key_id": "..."
  }
}
```

### Import/Export

#### POST `/api/certificates/import`

Importe un certificat.

**Corps de la requête (multipart/form-data) :**
- `file` : Fichier du certificat (PEM, DER, ou PKCS#12)
- `password` (optionnel) : Mot de passe pour PKCS#12
- `format` (optionnel) : Format du fichier (auto-détecté si non spécifié)

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "common_name": "example.com",
    "message": "Certificat importé avec succès"
  }
}
```

#### POST `/api/certificates/{cert_id}/export`

Exporte un certificat.

**Corps de la requête :**
```json
{
  "format": "PEM",
  "include_key": false,
  "password": "secret"  // Pour PKCS#12
}
```

**Réponse :**
Fichier téléchargeable selon le format demandé.

### Renouvellement

#### POST `/api/certificates/{cert_id}/renew`

Renouvelle un certificat.

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "common_name": "example.com",
    "message": "Certificat renouvelé avec succès"
  }
}
```

#### POST `/api/certificates/{cert_id}/verify-chain`

Vérifie la chaîne de certificats avec une CA.

**Corps de la requête :**
```json
{
  "ca_id": "..."
}
```

### CA (Autorités de certification)

#### GET `/api/ca`

Liste toutes les CA.

**Réponse :**
```json
{
  "success": true,
  "data": [
    {
      "id": "...",
      "common_name": "My Root CA",
      "is_root": true
    }
  ]
}
```

#### GET `/api/ca/{ca_id}`

Récupère les détails d'une CA.

#### POST `/api/ca/import`

Importe une CA.

**Corps de la requête (multipart/form-data) :**
- `file` : Fichier de la CA (PEM ou DER)

#### DELETE `/api/ca/{ca_id}`

Supprime une CA.

### Let's Encrypt

#### GET `/api/letsencrypt`

Liste tous les certificats Let's Encrypt.

#### POST `/api/letsencrypt/obtain`

Obtient un nouveau certificat Let's Encrypt.

**Corps de la requête :**
```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "staging": false,
  "validation_method": "standalone"
}
```

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "domain": "example.com",
    "message": "Certificat obtenu avec succès"
  }
}
```

#### POST `/api/letsencrypt/{cert_id}/renew`

Renouvelle un certificat Let's Encrypt.

#### POST `/api/letsencrypt/renew-all`

Renouvelle tous les certificats Let's Encrypt.

#### GET `/api/letsencrypt/check-certbot`

Vérifie si Certbot est installé et accessible.

### Certificats client

#### GET `/api/client-certificates`

Liste tous les certificats client.

#### POST `/api/client-certificates`

Crée un nouveau certificat client.

**Corps de la requête (multipart/form-data) :**
- `common_name` : Nom commun
- `validity_days` : Nombre de jours de validité
- `key_type` : Type de clé (RSA ou ECDSA)
- `key_size` : Taille de la clé
- `country`, `state`, `locality`, `organization`, `organizational_unit`, `email` (optionnels)
- `ca_cert_file` (optionnel) : Fichier de la CA pour signer
- `ca_key_file` (optionnel) : Fichier de la clé de la CA
- `ca_password` (optionnel) : Mot de passe de la clé CA

**Réponse :**
```json
{
  "success": true,
  "data": {
    "id": "...",
    "common_name": "client.example.com",
    "message": "Certificat client créé avec succès"
  }
}
```

#### POST `/api/client-certificates/{cert_id}/export-browser`

Exporte un certificat client en format PKCS#12 pour import dans un navigateur.

**Corps de la requête :**
```json
{
  "password": "secret"
}
```

**Réponse :**
Fichier `.p12` téléchargeable.

## Codes d'erreur HTTP

- `200` : Succès
- `400` : Requête invalide
- `404` : Ressource non trouvée
- `500` : Erreur serveur

## Exemples d'utilisation

### Avec curl

```bash
# Lister les certificats
curl http://127.0.0.1:8000/api/certificates

# Créer un certificat
curl -X POST http://127.0.0.1:8000/api/certificates \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "example.com",
    "validity_days": 365
  }'

# Importer un certificat
curl -X POST http://127.0.0.1:8000/api/certificates/import \
  -F "file=@cert.pem"
```

### Avec Python

```python
import requests

# Lister les certificats
response = requests.get("http://127.0.0.1:8000/api/certificates")
certificates = response.json()["data"]

# Créer un certificat
response = requests.post(
    "http://127.0.0.1:8000/api/certificates",
    json={
        "common_name": "example.com",
        "validity_days": 365
    }
)
result = response.json()
```

## Documentation interactive

L'API FastAPI fournit une documentation interactive accessible à :
- Swagger UI : `http://127.0.0.1:8000/docs`
- ReDoc : `http://127.0.0.1:8000/redoc`

## Ressources

- [Documentation complète](README.md)
- [Guide de développement](DEVELOPMENT.md)

