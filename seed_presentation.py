#!/usr/bin/env python3
"""
Jeu de données de démonstration pour présentation CertificationManager.

Usage:
    python seed_presentation.py
    python seed_presentation.py --quick          # ~25 certs
    CERTMANAGER_STORAGE_PATH=/data/.certmanager python seed_presentation.py

Dans Docker:
    docker compose cp seed_presentation.py certmanager:/app/seed_presentation.py
    docker compose exec certmanager python /app/seed_presentation.py
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

from src.core import CertificateManager, SecureStorage
from src.core.audit import AuditLogger
from src.core.ca_manager import CAManager
from src.core.certificate.client import ClientCertificateManager
from src.core.lifecycle import CertificateLifecycle
from src.core.renewal import CertificateRenewal


ORGANIZATIONS = [
    "ESGI Paris",
    "ESGI — Cryptographie",
    "Acme Corp",
    "TechSolutions SAS",
    "CloudOps France",
    "SecureBank",
    "MédiaPlus",
    "DataCenter Île-de-France",
    "DevOps Studio",
    "Startup.io",
]

ENVIRONMENTS = ["prod", "staging", "dev", "preprod", "demo", "internal"]
SERVICES = [
    "api", "www", "portal", "auth", "cdn", "mail", "vpn", "grafana",
    "jenkins", "gitlab", "vault", "kafka", "redis", "postgres", "mqtt",
    "payment", "billing", "analytics", "mobile-api", "admin",
]

PRESENTATION_HEROES = [
    ("portail.esgi.fr", 400, "ESGI Paris", ["www.esgi.fr", "portail.esgi.fr"], None, 4096),
    ("api.cryptographie.esgi.fr", 180, "ESGI — Cryptographie", ["api.cryptographie.esgi.fr"], ["10.0.1.50"], 2048),
    ("staging-api.esgi.fr", 14, "ESGI DevOps", ["staging-api.esgi.fr"], None, 2048),
    ("legacy-intranet.esgi.fr", 3, "ESGI IT", None, None, 2048),
    ("*.wildcard.esgi.fr", 90, "ESGI Paris", ["*.wildcard.esgi.fr"], None, 2048),
    ("vpn.securebank.fr", 5, "SecureBank", ["vpn.securebank.fr"], ["192.168.10.1"], 4096),
    ("payment.acme.com", 22, "Acme Corp", ["payment.acme.com", "pay.acme.com"], None, 2048),
    ("grafana.monitoring.io", 60, "CloudOps France", ["grafana.monitoring.io"], None, 2048),
    ("mail.techsolutions.fr", 120, "TechSolutions SAS", ["mail.techsolutions.fr", "smtp.techsolutions.fr"], None, 3072),
    ("auth.startup.io", 8, "Startup.io", ["auth.startup.io"], None, 2048),
]


@contextmanager
def _backdate(days: int):
    """Génère un certificat comme s'il avait été créé dans le passé."""
    fake_now = datetime.utcnow() - timedelta(days=days)

    class _FakeDatetime(datetime):
        @classmethod
        def utcnow(cls):
            return fake_now

    with patch("src.core.certificate.datetime", _FakeDatetime):
        with patch("src.core.certificate.client.datetime", _FakeDatetime):
            yield


def _save_server(
    cm: CertificateManager,
    storage: SecureStorage,
    cn: str,
    validity_days: int,
    organization: str,
    san_dns: Optional[List[str]] = None,
    san_ip: Optional[List[str]] = None,
    key_size: int = 2048,
    backdate_days: int = 0,
) -> str:
    if san_ip:
        san_ip = [ipaddress.ip_address(ip) for ip in san_ip]
    kwargs = dict(
        common_name=cn,
        validity_days=validity_days,
        organization=organization,
        country="FR",
        locality=random.choice(["Paris", "Lyon", "Marseille", None]),
        san_dns=san_dns,
        san_ip=san_ip,
        key_size=key_size,
    )
    if backdate_days > 0:
        with _backdate(backdate_days):
            cert, key, meta = cm.generate_self_signed_cert(**kwargs)
    else:
        cert, key, meta = cm.generate_self_signed_cert(**kwargs)
    return storage.save_certificate(cert, key, meta)


def _random_server_specs(count: int) -> List[Tuple[str, int, str]]:
    specs = []
    for i in range(count):
        env = random.choice(ENVIRONMENTS)
        svc = random.choice(SERVICES)
        domain = random.choice(["esgi.fr", "acme.com", "techsolutions.fr", "demo.io", "internal.local"])
        cn = f"{svc}.{env}.{domain}" if random.random() > 0.3 else f"{svc}.{domain}"
        days = random.choices(
            population=[1, 3, 5, 10, 20, 45, 90, 180, 365, 730],
            weights=[8, 8, 10, 12, 15, 15, 12, 10, 8, 2],
            k=1,
        )[0]
        org = random.choice(ORGANIZATIONS)
        specs.append((cn, days, org))
    return specs


def seed_audit_logs(storage_path: str, cert_ids: List[str], count: int = 40) -> int:
    audit = AuditLogger(storage_path)
    actions = [
        ("certificate.create", "certificate"),
        ("certificate.renew", "certificate"),
        ("certificate.delete", "certificate"),
        ("certificate.export", "certificate"),
        ("ca.import", "ca"),
        ("user.login", None),
        ("compliance.scan", None),
        ("settings.update", "config"),
    ]
    users = [
        ("admin", "admin-001"),
        ("operator", "op-001"),
        ("viewer", "view-001"),
    ]
    for i in range(count):
        action, rtype = random.choice(actions)
        user, uid = random.choice(users)
        rid = random.choice(cert_ids) if rtype == "certificate" and cert_ids else None
        audit.log(
            action=action,
            user_id=uid,
            username=user,
            resource_type=rtype,
            resource_id=rid,
            details={"demo": True, "index": i},
            success=random.random() > 0.05,
            ip_address=f"10.0.{random.randint(1, 50)}.{random.randint(2, 250)}",
        )
    return count


def seed_presentation(*, quick: bool = False) -> Dict[str, Any]:
    storage = SecureStorage()
    cm = CertificateManager()
    ca_mgr = CAManager(storage)
    client_mgr = ClientCertificateManager()
    renewal = CertificateRenewal(storage)

    stats: Dict[str, Any] = {
        "server_certs": 0,
        "expired": 0,
        "client_certs": 0,
        "csrs": 0,
        "cas": 0,
        "archives": 0,
        "audit_logs": 0,
        "errors": 0,
    }
    cert_ids: List[str] = []

    print("🎬 CertificationManager — seed présentation")
    print(f"   Stockage : {storage.storage_path}\n")

    # --- Certificats « héros » pour la démo ---
    print("📌 Certificats scénarios (noms reconnaissables)…")
    for cn, days, org, san_dns, san_ip, key_size in PRESENTATION_HEROES:
        try:
            cid = _save_server(cm, storage, cn, days, org, san_dns, san_ip, key_size)
            cert_ids.append(cid)
            stats["server_certs"] += 1
            print(f"   ✓ {cn:<35} {days:>3}j  {org}")
        except Exception as e:
            stats["errors"] += 1
            print(f"   ✗ {cn}: {e}")

    # --- Certificats expirés ---
    expired_count = 3 if quick else 12
    print(f"\n⏰ Certificats expirés ({expired_count})…")
    for i in range(expired_count):
        cn = f"expired-{i + 1:02d}.{random.choice(['legacy.fr', 'old.acme.com', 'retired.esgi.fr'])}"
        try:
            # Créé il y a 400j, validité 365j → expiré depuis ~35j
            cid = _save_server(
                cm, storage, cn, 365, random.choice(ORGANIZATIONS),
                backdate_days=400,
            )
            cert_ids.append(cid)
            stats["server_certs"] += 1
            stats["expired"] += 1
            print(f"   ✓ {cn}")
        except Exception as e:
            stats["errors"] += 1
            print(f"   ✗ {cn}: {e}")

    # --- Volume aléatoire ---
    bulk = 10 if quick else 55
    print(f"\n📦 Certificats serveur aléatoires ({bulk})…")
    for cn, days, org in _random_server_specs(bulk):
        try:
            san = None
            if random.random() < 0.25:
                san = [f"www.{cn}", cn]
            cid = _save_server(cm, storage, cn, days, org, san_dns=san)
            cert_ids.append(cid)
            stats["server_certs"] += 1
        except Exception as e:
            stats["errors"] += 1
    print(f"   ✓ {bulk} certificats générés")

    # --- CA interne + certs signés ---
    print("\n🏛️  Autorité de certification interne…")
    try:
        ca_id = ca_mgr.generate_ca(
            common_name="ESGI Root CA",
            name="ESGI Root CA",
            organization="ESGI Paris",
            country="FR",
            validity_days=3650,
            key_size=4096,
        )
        stats["cas"] += 1
        print(f"   ✓ CA racine : ESGI Root CA ({ca_id[:8]}…)")

        for cn, days in [
            ("intranet.esgi.fr", 365),
            ("api-signed.esgi.fr", 180),
            ("services.esgi.fr", 90),
        ]:
            cid = ca_mgr.sign_server_certificate(
                ca_id=ca_id,
                common_name=cn,
                validity_days=days,
                organization="ESGI Paris",
                country="FR",
            )
            cert_ids.append(cid)
            stats["server_certs"] += 1
            print(f"   ✓ Signé par CA : {cn}")
    except Exception as e:
        stats["errors"] += 1
        print(f"   ✗ CA : {e}")

    # --- Certificats client mTLS ---
    client_count = 2 if quick else 6
    print(f"\n👤 Certificats client mTLS ({client_count})…")
    for i in range(client_count):
        cn = f"user{i + 1}@esgi.fr"
        try:
            cert, key, meta = client_mgr.generate_client_cert(
                common_name=cn,
                organization="ESGI Paris",
                country="FR",
                email=cn,
                validity_days=random.choice([90, 180, 365]),
            )
            meta["certificate_type"] = "client"
            cid = storage.save_certificate(cert, key, meta)
            cert_ids.append(cid)
            stats["client_certs"] += 1
            print(f"   ✓ {cn}")
        except Exception as e:
            stats["errors"] += 1
            print(f"   ✗ {cn}: {e}")

    # --- CSR en attente ---
    csr_count = 2 if quick else 5
    print(f"\n📝 CSR en attente ({csr_count})…")
    for i in range(csr_count):
        cn = f"pending-{i + 1}.esgi.fr"
        try:
            csr, key, meta = cm.generate_csr(
                common_name=cn,
                organization="ESGI Paris",
                country="FR",
                san_dns=[cn, f"www.{cn}"],
            )
            storage.save_csr(csr, key, meta)
            stats["csrs"] += 1
            print(f"   ✓ {cn}")
        except Exception as e:
            stats["errors"] += 1
            print(f"   ✗ {cn}: {e}")

    # --- Archives (renouvellement) ---
    archive_count = 1 if quick else 4
    print(f"\n📁 Archives via renouvellement ({archive_count})…")
    renewable = [c for c in storage.list_certificates() if not c.get("is_expired")][:archive_count + 5]
    archived = 0
    for meta in renewable:
        if archived >= archive_count:
            break
        cid = meta.get("id")
        if not cid or meta.get("certificate_type") == "client":
            continue
        try:
            renewal.renew_certificate(cid, archive_old=True)
            archived += 1
            stats["archives"] += 1
            print(f"   ✓ Archivé + renouvelé : {meta.get('common_name', cid[:8])}")
        except Exception:
            continue

    # --- Journal d'audit ---
    audit_count = 15 if quick else 45
    print(f"\n📋 Entrées d'audit ({audit_count})…")
    stats["audit_logs"] = seed_audit_logs(str(storage.storage_path), cert_ids, audit_count)
    print(f"   ✓ {stats['audit_logs']} entrées")

    # --- Résumé lifecycle ---
    lifecycle = CertificateLifecycle(storage)
    summary = lifecycle.get_statistics()
    alerts = lifecycle.get_expiring_certificates(days_threshold=60, include_expired=True)

    print("\n" + "=" * 60)
    print("✅ Jeu de démo prêt pour la présentation !")
    print("=" * 60)
    print(f"   Certificats serveur : {stats['server_certs']}")
    print(f"   Dont expirés        : {stats['expired']}")
    print(f"   Certificats client  : {stats['client_certs']}")
    print(f"   CSR en attente      : {stats['csrs']}")
    print(f"   CA                  : {stats['cas']}")
    print(f"   Archives            : {stats['archives']}")
    print(f"   Logs audit          : {stats['audit_logs']}")
    if stats["errors"]:
        print(f"   Erreurs             : {stats['errors']}")
    print()
    print("📊 Statistiques dashboard :")
    print(f"   Total    : {summary.get('total', 0)}")
    print(f"   Valides  : {summary.get('valid', 0)}")
    print(f"   Expirent : {summary.get('expiring_soon', 0)} + critique {summary.get('critical', 0)}")
    print(f"   Expirés  : {summary.get('expired', 0)}")
    print(f"   Alertes  : {len(alerts)}")
    print()
    print("🌐 Ouvrez http://127.0.0.1:8000 pour la démo")
    print("   Onglets recommandés : Certificats → Alertes → Paramètres (conformité) → Audit")

    return {**stats, "summary": summary, "alerts_count": len(alerts)}


def main():
    parser = argparse.ArgumentParser(description="Seed données de présentation CertificationManager")
    parser.add_argument("--quick", action="store_true", help="Jeu réduit (~25 certs)")
    args = parser.parse_args()
    try:
        seed_presentation(quick=args.quick)
    except KeyboardInterrupt:
        print("\nInterrompu.")
        sys.exit(1)


if __name__ == "__main__":
    main()
