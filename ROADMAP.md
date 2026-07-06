# 🗺️ Roadmap - CertificationManager

Cette roadmap détaille le plan de développement du projet par ordre de priorité.

## 📊 Vue d'ensemble des phases

| Phase | Durée estimée | Priorité | Statut |
|-------|---------------|-----------|--------|
| Phase 1 - MVP | 4 semaines | 🔴 Critique | ✅ **Terminé** |
| Phase 2 - Gestion | 4 semaines | 🟠 Haute | 🟡 **En cours** (25% - Cycle de vie terminé) |
| Phase 3 - Interface | 4 semaines | 🟡 Moyenne | 🟡 **En cours** (70% - API + Web UI terminés) |
| Phase 4 - Avancé | 8+ semaines | 🟢 Basse | ⏳ À faire |

---

## ✅ Phase 1 - MVP (Minimum Viable Product) - **TERMINÉ**

**Objectif** : Créer une application fonctionnelle de base permettant de générer et gérer des certificats.

**Statut** : ✅ **Complété** - Toutes les fonctionnalités de base sont opérationnelles.

### Semaine 1 : Infrastructure et configuration

#### Priorité 1.1 - Configuration du projet
- [x] Structure des répertoires
- [x] Configuration Python (setup.py ou pyproject.toml)
- [x] Gestion des dépendances (requirements.txt)
- [x] Configuration Git (.gitignore)
- [x] Configuration de l'environnement virtuel
- [x] Configuration des outils de développement (black, flake8, mypy)
- [x] Configuration des tests (pytest)

#### Priorité 1.2 - Bibliothèques cryptographiques
- [x] Installation et configuration de `cryptography`
- [x] Installation et configuration de `pyOpenSSL` (optionnel)
- [x] Tests de base des fonctionnalités cryptographiques

### Semaine 2 : Génération de certificats

#### Priorité 2.1 - Génération de clés
- [x] Module de génération de clés RSA
- [x] Module de génération de clés ECDSA
- [x] Support de différentes tailles de clés (2048, 3072, 4096 bits)
- [x] Export des clés en format PEM
- [x] Export des clés en format DER
- [x] Tests unitaires pour la génération de clés

#### Priorité 2.2 - Génération de certificats auto-signés
- [x] Module de création de certificats X.509
- [x] Support des champs standards (CN, O, OU, C, ST, L)
- [x] Support des extensions (SAN, Key Usage, Extended Key Usage, Basic Constraints)
- [x] Génération de certificats avec dates de validité
- [x] Export en format PEM
- [x] Export en format DER
- [x] Tests unitaires pour la génération de certificats

#### Priorité 2.3 - Génération de CSR (Certificate Signing Request)
- [x] Module de création de CSR
- [x] Support des mêmes champs que les certificats
- [x] Export en format PEM
- [x] Tests unitaires pour les CSR

### Semaine 3 : Stockage et gestion

#### Priorité 3.1 - Système de stockage
- [x] Architecture de stockage local (fichiers)
- [x] Structure de répertoires pour certificats et clés
- [x] Chiffrement des clés privées stockées (optionnel avec mot de passe)
- [x] Gestion des permissions (chmod 600 pour les clés, 700 pour répertoires)
- [x] Module de sauvegarde et restauration
- [x] Tests pour le stockage

#### Priorité 3.2 - Métadonnées et indexation
- [x] Système de métadonnées pour chaque certificat (JSON)
- [x] Indexation par nom commun (CN)
- [x] Indexation par date d'expiration
- [x] Recherche de certificats
- [x] Tests pour les métadonnées

### Semaine 4 : CLI et validation

#### Priorité 4.1 - Interface en ligne de commande (CLI)
- [x] Framework CLI (Click)
- [x] Commande `generate` (certificat auto-signé)
- [x] Commande `csr` (génération de CSR)
- [x] Commande `list` (lister les certificats)
- [x] Commande `info` (détails d'un certificat)
- [x] Commande `delete` (supprimer un certificat)
- [x] Gestion des erreurs et messages utilisateur
- [x] Tests d'intégration CLI

#### Priorité 4.2 - Validation de certificats
- [x] Module de validation de certificats
- [x] Vérification de la date d'expiration
- [x] Vérification de la signature (basique)
- [x] Vérification de la chaîne de certificats (basique)
- [x] Vérification des extensions critiques
- [x] Commande CLI `verify`
- [x] Tests de validation

---

## 🟠 Phase 2 - Gestion avancée - 🟡 **EN COURS**

**Objectif** : Ajouter des fonctionnalités de gestion du cycle de vie des certificats.

**Statut** : 🟡 **En cours** - Cycle de vie et alertes terminés. Renouvellement et Import/Export à venir.

### Semaine 5 : Cycle de vie - ✅ **TERMINÉ**

#### Priorité 5.1 - Suivi des certificats
- [x] Système de suivi des dates d'expiration
- [x] Calcul automatique des jours restants
- [x] Catégorisation par statut (valide, expiré, expirant bientôt)
- [x] Commande CLI `status` (statut global ou par certificat)
- [x] Commande CLI `expiring` (certificats expirant bientôt)
- [x] Statistiques globales
- [ ] Tests de suivi (à compléter)

#### Priorité 5.2 - Alertes et notifications
- [x] Système d'alertes configurable
- [x] Alertes en ligne de commande
- [x] Configuration des seuils d'alerte (7, 30, 60 jours par défaut)
- [x] Commande CLI `alerts`
- [x] Niveaux d'alerte (info, warning, critical, error)
- [x] Endpoints API pour les alertes
- [ ] Alertes par email (optionnel - à venir)
- [ ] Alertes dans l'interface web (en cours)
- [ ] Tests d'alertes (à compléter)

### Semaine 6 : Renouvellement - ✅ **TERMINÉ**

#### Priorité 6.1 - Renouvellement manuel
- [x] Commande CLI `renew` pour renouveler un certificat
- [x] Génération automatique d'un nouveau certificat avec les mêmes paramètres
- [x] Archivage de l'ancien certificat
- [x] Endpoint API pour le renouvellement
- [x] Bouton de renouvellement dans l'interface web
- [x] Bouton de renouvellement dans les alertes
- [ ] Tests de renouvellement (à compléter)

#### Priorité 6.2 - Renouvellement automatique (optionnel)
- [ ] Système de tâches planifiées (cron-like)
- [ ] Détection automatique des certificats à renouveler
- [ ] Renouvellement automatique avec notification
- [ ] Tests de renouvellement automatique

### Semaine 7 : Import/Export - ✅ **TERMINÉ**

#### Priorité 7.1 - Import de certificats
- [x] Import depuis fichier PEM
- [x] Import depuis fichier DER
- [x] Import depuis PKCS#12 (.p12, .pfx)
- [x] Import avec mot de passe pour PKCS#12
- [x] Validation lors de l'import
- [x] Commande CLI `import`
- [x] Endpoint API pour l'import
- [x] Interface web pour l'import
- [ ] Tests d'import (à compléter)

#### Priorité 7.2 - Export de certificats
- [x] Export en format PEM
- [x] Export en format DER
- [x] Export en format PKCS#12
- [x] Export avec protection par mot de passe
- [x] Export de la clé privée séparément
- [x] Commande CLI `export`
- [x] Endpoint API pour l'export
- [x] Interface web pour l'export
- [ ] Tests d'export (à compléter)

### Semaine 8 : Gestion des CA - ✅ **TERMINÉ**

#### Priorité 8.1 - Autorités de certification
- [x] Support des certificats CA
- [x] Stockage séparé des CA
- [x] Vérification de la chaîne de certificats avec CA
- [x] Import de CA racines
- [x] Commande CLI `ca` pour gérer les CA
- [x] Endpoints API pour les CA
- [x] Interface web pour les CA
- [ ] Tests CA (à compléter)

---

## 🟡 Phase 3 - Interface et intégration - **EN COURS**

**Objectif** : Créer des interfaces utilisateur et une API pour faciliter l'utilisation.

**Statut** : 🟡 **En cours** - API REST et Interface Web terminées. Authentification et intégrations à venir.

### Semaine 9 : API REST - ✅ **TERMINÉ**

#### Priorité 9.1 - Infrastructure API
- [x] Framework web (FastAPI)
- [x] Structure de l'API REST
- [x] Gestion des erreurs HTTP
- [x] Documentation API (Swagger/OpenAPI intégré dans FastAPI)
- [ ] Tests d'API (à compléter)

#### Priorité 9.2 - Endpoints de base
- [x] `GET /api/certificates` - Liste des certificats
- [x] `GET /api/certificates/{id}` - Détails d'un certificat
- [x] `POST /api/certificates` - Créer un certificat
- [x] `DELETE /api/certificates/{id}` - Supprimer un certificat
- [x] `GET /api/certificates/{id}/verify` - Vérifier un certificat
- [x] `POST /api/csr` - Créer une CSR
- [ ] Tests des endpoints (à compléter)

### Semaine 10 : Interface web - ✅ **TERMINÉ**

#### Priorité 10.1 - Dashboard de base
- [x] Framework frontend (HTML/CSS/JavaScript vanilla)
- [x] Page de liste des certificats
- [x] Page de détails d'un certificat (modal)
- [x] Formulaire de création de certificat
- [x] Design responsive et moderne
- [x] Interface épurée et intuitive

#### Priorité 10.2 - Fonctionnalités web
- [x] Recherche en temps réel
- [x] Filtres et recherche
- [x] Notifications visuelles (toast)
- [x] Gestion des erreurs
- [x] Chargement asynchrone
- [x] Graphiques d'expiration (timeline et répartition)
- [x] Dashboard avec statistiques visuelles
- [x] Actions en masse (sélection multiple, renouvellement, export, suppression)
- [x] Filtres avancés (statut, type de clé, expiration, organisation)
- [ ] Tests d'intégration (à compléter)

### Semaine 11 : Authentification - ⏳ **À FAIRE**

#### Priorité 11.1 - Système d'authentification
- [ ] Authentification par token (JWT)
- [ ] Gestion des utilisateurs
- [ ] Rôles et permissions
- [ ] Protection des endpoints sensibles
- [ ] Tests d'authentification

#### Priorité 11.2 - Sécurité API
- [ ] Rate limiting
- [x] Validation des entrées (Pydantic)
- [ ] Protection CSRF
- [ ] Logs d'audit
- [ ] Tests de sécurité

### Semaine 12 : Intégrations - 🟡 **EN COURS**

#### Priorité 12.1 - Let's Encrypt - ✅ **TERMINÉ**
- [x] Intégration avec Let's Encrypt (ACME via certbot)
- [x] Génération automatique de certificats Let's Encrypt
- [x] Renouvellement automatique
- [x] Commande CLI pour Let's Encrypt
- [x] Support staging et production
- [x] Endpoints API pour Let's Encrypt
- [x] Interface web pour Let's Encrypt
- [ ] Tests d'intégration (à compléter)

#### Priorité 12.2 - Autres services
- [ ] Support d'autres CA publiques
- [ ] Webhooks pour notifications
- [ ] Tests d'intégration

---

## 🟢 Phase 4 - Fonctionnalités avancées

**Objectif** : Ajouter des fonctionnalités avancées et optimisations.

### Semaines 13-14 : Certificats avancés

#### Priorité 13.1 - Certificats wildcard
- [x] Support des certificats wildcard (*.example.com)
- [x] Validation des noms de domaine
- [ ] Tests wildcard

#### Priorité 13.2 - Certificats client
- [x] Génération de certificats client (mutual TLS)
- [x] Gestion des certificats client
- [x] Export pour navigateurs
- [ ] Tests certificats client

### Semaines 15-16 : Audit et sécurité

#### Priorité 15.1 - Audit et journalisation
- [ ] Système de logs détaillés
- [ ] Journalisation de toutes les opérations
- [ ] Export des logs
- [ ] Recherche dans les logs
- [ ] Tests d'audit

#### Priorité 15.2 - Sécurité renforcée
- [ ] Chiffrement avancé des clés privées
- [ ] Support HSM (Hardware Security Module)
- [ ] Rotation des clés
- [ ] Tests de sécurité

### Semaines 17-18 : Performance et optimisation

#### Priorité 17.1 - Optimisation
- [ ] Optimisation des requêtes
- [ ] Mise en cache
- [ ] Indexation améliorée
- [ ] Tests de performance

#### Priorité 17.2 - Scalabilité
- [ ] Support de bases de données (PostgreSQL, MySQL)
- [ ] Architecture distribuée (optionnel)
- [ ] Tests de charge

### Semaines 19+ : Documentation et communauté

#### Priorité 19.1 - Documentation
- [ ] Documentation complète de l'API
- [ ] Guides d'utilisation
- [ ] Tutoriels vidéo (optionnel)
- [ ] Documentation de contribution

#### Priorité 19.2 - Communauté
- [ ] Badges et métriques
- [ ] Templates GitHub (issues, PR)
- [ ] Code de conduite
- [ ] Guide de contribution détaillé

---

## 📋 Checklist de priorité globale

### 🔴 Critique (Doit être fait en premier) - ✅ **TERMINÉ**
1. ✅ Infrastructure de base
2. ✅ Génération de certificats auto-signés
3. ✅ Génération de CSR
4. ✅ Stockage sécurisé
5. ✅ CLI fonctionnelle
6. ✅ Validation de base

### 🟠 Haute (Important pour l'utilité) - ⏳ **EN ATTENTE**
1. ⏳ Gestion du cycle de vie
2. ⏳ Alertes d'expiration
3. ⏳ Import/Export
4. ⏳ Renouvellement

### 🟡 Moyenne (Améliore l'expérience) - 🟡 **EN COURS**
1. ✅ API REST
2. ✅ Interface web
3. ⏳ Authentification
4. ⏳ Intégrations

### 🟢 Basse (Nice to have) - ⏳ **À FAIRE**
1. ⏳ Fonctionnalités avancées
2. ⏳ Optimisations
3. ⏳ Documentation avancée

---

## 🎯 Critères de succès par phase

### Phase 1 - MVP ✅ **TERMINÉ**
- ✅ Générer un certificat auto-signé en une commande
- ✅ Lister et afficher les certificats stockés
- ✅ Valider un certificat
- ✅ Documentation de base fonctionnelle
- ✅ CLI complète et fonctionnelle
- ✅ Tests unitaires de base

### Phase 2 - Gestion ⏳ **À FAIRE**
- ⏳ Détecter les certificats expirant bientôt
- ⏳ Renouveler un certificat
- ⏳ Importer/Exporter des certificats
- ⏳ Alertes d'expiration

### Phase 3 - Interface 🟡 **EN COURS**
- ✅ API REST fonctionnelle (FastAPI)
- ✅ Interface web utilisable et moderne
- ⏳ Authentification sécurisée (à venir)
- ⏳ Tests d'intégration complets (à compléter)

### Phase 4 - Avancé ⏳ **À FAIRE**
- ⏳ Support de cas d'usage avancés
- ⏳ Performance acceptable
- ⏳ Documentation complète

---

## 📝 Notes

- Les durées sont des estimations et peuvent varier
- Les priorités peuvent être ajustées selon les besoins
- Certaines fonctionnalités peuvent être développées en parallèle
- Les tests doivent être écrits en même temps que le code

---

## 📈 Progression globale

**Statut actuel** : 🟢 **v0.2 — Base saine + P1 sécurité en cours**

- ✅ **Phase 1 (MVP)** : 100 %
- ✅ **Phase 2 (Gestion)** : 100 %
- ✅ **Phase 3 (Interface)** : 95 %
  - ✅ API REST, Web UI, Let's Encrypt, graphiques, bulk actions
  - 🔧 Authentification JWT (optionnelle, implémentée)
  - 🔧 Tests d'intégration (34 tests automatisés)
- 🔧 **Phase 4 (v2 — Production)** : 40 %
  - ✅ Sprint 0 stabilisation
  - ✅ CI/CD + Docker
  - 🔧 Sécurité (auth, rate limit, permissions)
  - ⬜ Audit, backup, scheduler

**Prochaines étapes** :
1. Compléter tests (lifecycle, import_export, ca_manager) → 80 % couverture
2. Audit logs (`src/core/audit.py`)
3. Chiffrement clés par défaut
4. Epic 4 — Génération CA, backup/restore

Voir [TODO-V2.md](TODO-V2.md) pour le détail.

---

**Dernière mise à jour** : Décembre 2024

