# Guide de déploiement production

## Docker (recommandé)

```bash
cp config/.env.example config/.env
# Éditer : CERTMANAGER_AUTH_ENABLED=true, CERTMANAGER_ADMIN_PASSWORD, etc.

docker compose up -d
```

L'application écoute sur le port `8000` (configurable via `CERTMANAGER_PORT`).

## Variables d'environnement essentielles

| Variable | Description | Production |
|----------|-------------|------------|
| `CERTMANAGER_AUTH_ENABLED` | Auth JWT | `true` |
| `CERTMANAGER_ADMIN_PASSWORD` | Mot de passe admin initial | Obligatoire |
| `CERTMANAGER_JWT_SECRET` | Secret JWT | Chaîne aléatoire 32+ octets |
| `CERTMANAGER_ENCRYPT_KEYS` | Chiffrement clés privées | `true` |
| `CERTMANAGER_STORAGE_PASSWORD` | Mot de passe chiffrement | Fort, unique |
| `CERTMANAGER_RATE_LIMIT_ENABLED` | Rate limiting | `true` |
| `CERTMANAGER_CORS_ORIGINS` | Origines autorisées | Domaine exact |

## HTTPS

### Option A — CLI avec certificats

```bash
certmanager web --host 0.0.0.0 --port 8443 \
  --ssl-certfile /path/to/cert.pem \
  --ssl-keyfile /path/to/key.pem
```

### Option B — Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name certmanager.example.com;

    ssl_certificate     /etc/ssl/certs/certmanager.crt;
    ssl_certificate_key /etc/ssl/private/certmanager.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Systemd

Voir `deploy/systemd/certmanager.service`.

## Kubernetes

Voir `deploy/k8s/deployment.yaml`.

## Sauvegarde

```bash
certmanager backup -o backup-$(date +%Y%m%d).tar.gz --password "mot-de-passe"
```

Planifier via cron ou le scheduler intégré.

## Monitoring

Endpoint Prometheus (auth requise si activée) :

```
GET /api/metrics
```

Métriques : `certmanager_certificates_total`, `certmanager_certificates_expired`, etc.
