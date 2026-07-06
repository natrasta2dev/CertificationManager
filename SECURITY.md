# Politique de sécurité

## Versions supportées

| Version | Supportée          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Signaler une vulnérabilité

Si vous découvrez une faille de sécurité :

1. **Ne pas** ouvrir d'issue publique GitHub
2. Contacter le mainteneur via les issues privées ou email du dépôt
3. Inclure : description, étapes de reproduction, impact estimé

Délai de réponse visé : 7 jours ouvrés.

## Bonnes pratiques de déploiement

- Activer l'authentification : `CERTMANAGER_AUTH_ENABLED=true`
- Définir `CERTMANAGER_ADMIN_PASSWORD` et `CERTMANAGER_JWT_SECRET` forts
- Activer le chiffrement des clés : `CERTMANAGER_ENCRYPT_KEYS=true`
- Exposer l'API uniquement derrière HTTPS (reverse proxy ou `--ssl-certfile`)
- Limiter CORS aux origines connues
- Permissions stockage : répertoire `~/.certmanager` en `700`, clés en `600`

## Données sensibles

Les clés privées et mots de passe ne doivent jamais être commités.
Utiliser `.env` (voir `config/.env.example`) hors du dépôt.
