# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [0.2.0] - 2026-07-06

### Added

- Authentification JWT (access + refresh), rôles admin/operator/viewer, page login
- Audit logs JSON Lines, export CSV/JSON, onglet Audit
- Chiffrement optionnel des clés privées (`CERTMANAGER_ENCRYPT_KEYS`)
- Rate limiting, CSRF, CORS configurable, HTTPS CLI
- Génération CA racine/intermédiaire, signature serveur et CSR
- Backup/restore chiffré, renouvellement batch, renouvellement CA locale
- Scheduler (alertes, auto-renew, compliance-scan, rapport hebdomadaire)
- Notifications SMTP, webhooks HMAC, configuration via API
- Pagination API certificats, archives, liste CSR UI, paramètres web
- Mode sombre, scan conformité, métriques Prometheus `/api/metrics`
- Export CSV inventaire/archives, `certmanager config`
- Support SAN IP (CLI, API, web)
- Docker, docker-compose, CI GitHub Actions
- 133+ tests (unitaires + intégration), ~61 % couverture

### Changed

- Refactoring FastAPI en routers modulaires
- Configuration centralisée (`src/config/`, `.env`)
- Suppression du doublon `src/core/certificate.py`
- Version CLI dynamique depuis `pyproject.toml`

### Fixed

- Export bulk web, Let's Encrypt obtain 422, timezone certificats
- Renouvellement préservant l'émetteur (CA/LE/auto-signé)
- Validation signature certificats, filtres organisation

### Removed

- Script manuel `test_api.py` (remplacé par pytest)

## [0.1.0] - 2025

Version initiale : génération certificats, CSR, CLI, API REST, interface web.
