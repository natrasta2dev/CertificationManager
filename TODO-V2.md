# CertificationManager v2 — Todo list complète

> **Objectif v2** : passer d'un outil PKI local fonctionnel (v1) à une application **production-ready** : sécurisée, testée, déployable, maintenable et complète sur le cycle de vie des certificats.
>
> **Dernière mise à jour** : Juillet 2026  
> **Version** : 0.2.0  
> **Base** : Sprint 0 ✅ | Epics 1–8 largement livrés ✅

---

## Progression v2

| Epic | Statut | Détail |
|------|--------|--------|
| Sprint 0 — Stabilisation | ✅ | Bugs critiques, routers, config |
| Epic 1 — Tests & qualité | 🔧 | 133 tests, ~61 % couverture (objectif 80 %) |
| Epic 2 — CI/CD | ✅ | GitHub Actions, Docker, systemd/k8s exemples |
| Epic 3 — Sécurité & auth | ✅ | JWT, users, rôles, audit, CSRF, rate limit |
| Epic 4 — PKI & core | ✅ | CA, backup, conformité, san_ip, archives |
| Epic 5 — Automatisation | ✅ | Scheduler, SMTP, webhooks, rapport hebdo |
| Epic 6 — Interface web v2 | 🔧 | Pagination, archives, CSR, paramètres, mode sombre, raccourcis |
| Epic 7 — CLI v2 | 🔧 | config, san_ip, version dynamique |
| Epic 8 — API v2 | 🔧 | Pagination, métriques, rate-limit headers, config API |
| Epic 10 — Rapports | 🔧 | CSV, scan conformité |
| Epic 12 — Documentation | 🔧 | CHANGELOG, SECURITY, DEPLOYMENT |
| Epic 13 — Innovations | 🔧 | Prometheus `/api/metrics` |

### Reste pour v2.1+

- Couverture 80 %, pre-commit, mypy strict
- API versioning `/api/v1/`, WebSockets alertes
- ACME natif, export K8s/Vault
- Refactoring frontend (modules ES)
- PDF rapports, i18n

Voir sections détaillées ci-dessous pour le détail item par item.

## Légende

| Symbole | Signification |
|---------|---------------|
| ✅ | Fait |
| 🔧 | Partiel |
| ⬜ | À faire v2 |

---

## Sprint 0 — Stabilisation ✅

Tous les items critiques sont terminés (bugs export bulk, LE 422, timezone, renewal, doublon certificate.py, routers, config `.env`).

---

## Epic 1 — Tests & qualité 🔧

- [x] 133 tests unitaires + intégration
- [x] ~61 % couverture
- [ ] Objectif 80 % couverture
- [ ] pre-commit (black, isort, flake8, mypy)
- [x] CI seuil couverture 60 %

---

## Epic 2 — CI/CD ✅

- [x] GitHub Actions, Dockerfile, docker-compose, Makefile
- [x] Exemples `deploy/systemd/`, `deploy/k8s/`
- [x] Badges README
- [ ] Publication PyPI (optionnel)

---

## Epic 3 — Sécurité & auth ✅

JWT, rôles, login, CSRF, rate limit, chiffrement clés, audit logs, HTTPS CLI — **complet**.

---

## Epic 4 — PKI & core ✅

- [x] Génération CA, signature, renouvellement intelligent, CSR, backup/restore
- [x] san_ip, archives, compliance scanner
- [ ] OCSP/CRL (optionnel)
- [ ] SQLite/PostgreSQL (optionnel)

---

## Epic 5 — Automatisation ✅

Scheduler, SMTP, webhooks, rapport hebdomadaire — **complet**.

---

## Epic 6 — Interface web v2 🔧

- [x] Pagination, archives, CSR liste, paramètres, mode sombre
- [x] Vérification chaîne CA (modal), scan conformité
- [x] Raccourcis clavier (`/`, `n`, `r`, `Esc`)
- [ ] WebSockets, i18n, refactoring `app.js`

---

## Epic 7 — CLI v2 🔧

- [x] `certmanager config`, `--san-ip`, version dynamique, backup/restore
- [ ] Formats sortie json/yaml/csv, auto-complétion shell

---

## Epic 8 — API v2 🔧

- [x] Pagination, rate-limit headers, `/api/config`, `/api/metrics`
- [ ] Versioning `/api/v1/`, bulk endpoints officiels, WebSocket

---

## Epic 9–13 — Backlog

ACME natif, export K8s/Vault, cache performance, PDF rapports, HSM — **v2.1+**.

---

## Epic 12 — Documentation 🔧

- [x] CHANGELOG.md, SECURITY.md, docs/DEPLOYMENT.md
- [x] README, TODO-V2 alignés
- [ ] docs/API.md complet, FAQ, tutoriels

---

## Critères de succès v2

- [x] CI verte, Docker, backup/restore testé, zéro bug critique Sprint 0
- [x] Auth + chiffrement disponibles (activables en production)
- [ ] Couverture ≥ 80 %
- [ ] Performance 500 certs < 2 s (benchmark à ajouter)

