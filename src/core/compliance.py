"""Scan de conformité des certificats (algorithmes, tailles de clés, expiration)."""

from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .storage import SecureStorage
from .validation import CertificateValidator


class ComplianceScanner:
    """Analyse la conformité d'un inventaire de certificats."""

    WEAK_SIGNATURE_OIDS = {
        "sha1WithRSAEncryption",
        "md5WithRSAEncryption",
        "ecdsa-with-SHA1",
    }

    def __init__(self, storage: Optional[SecureStorage] = None):
        if storage is None:
            from ..config import get_settings
            storage = SecureStorage(storage_path=get_settings().storage_path)
        self.storage = storage
        self.validator = CertificateValidator()

    def scan_certificate(
        self,
        cert: x509.Certificate,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Retourne la liste des problèmes de conformité pour un certificat."""
        issues: List[str] = []
        meta = metadata or {}

        is_valid, errors = self.validator.validate_certificate(cert)
        if not is_valid:
            issues.extend(errors)

        sig_oid = cert.signature_algorithm_oid._name
        if sig_oid in self.WEAK_SIGNATURE_OIDS:
            issues.append(f"Algorithme de signature faible: {sig_oid}")

        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            if key_size < 2048:
                issues.append(f"Clé RSA faible: {key_size} bits (< 2048)")

        meta_key_size = meta.get("key_size")
        if meta_key_size and meta_key_size < 2048:
            issues.append(f"Métadonnée: clé RSA {meta_key_size} bits")

        if meta.get("key_type") == "RSA" and not meta_key_size:
            pass

        return issues

    def scan_all(self) -> Dict[str, Any]:
        """Scanne tous les certificats stockés."""
        certificates = self.storage.list_certificates()
        issues: List[Dict[str, Any]] = []
        compliant = 0

        for meta in certificates:
            cert_id = meta.get("id")
            if not cert_id:
                continue
            try:
                cert, _ = self.storage.load_certificate(cert_id)
                cert_issues = self.scan_certificate(cert, meta)
                if cert_issues:
                    issues.append({
                        "cert_id": cert_id,
                        "common_name": meta.get("common_name"),
                        "errors": cert_issues,
                    })
                else:
                    compliant += 1
            except Exception as e:
                issues.append({
                    "cert_id": cert_id,
                    "common_name": meta.get("common_name"),
                    "errors": [str(e)],
                })

        total = len(certificates)
        return {
            "total": total,
            "compliant": compliant,
            "issues_count": len(issues),
            "issues": issues,
            "compliance_rate": round((compliant / total) * 100, 1) if total else 100.0,
        }

    def guidelines_dashboard(self) -> Dict[str, Any]:
        """Tableau de bord conformité Mozilla / NIST."""
        scan = self.scan_all()
        certs = self.storage.list_certificates()
        stats = {
            "sha256_signatures": 0,
            "weak_signatures": 0,
            "rsa_2048_plus": 0,
            "rsa_weak": 0,
            "ecdsa_keys": 0,
            "expired": 0,
            "expiring_30d": 0,
            "valid_long_term": 0,
        }
        mozilla_checks = {
            "signature_sha256": {"pass": 0, "fail": 0},
            "rsa_key_2048": {"pass": 0, "fail": 0},
            "not_expired": {"pass": 0, "fail": 0},
            "validity_under_825_days": {"pass": 0, "fail": 0},
        }

        for meta in certs:
            cert_id = meta.get("id")
            if not cert_id:
                continue
            try:
                cert, _ = self.storage.load_certificate(cert_id)
                sig = cert.signature_algorithm_oid._name
                if "sha256" in sig.lower() or "ecdsa" in sig.lower():
                    stats["sha256_signatures"] += 1
                    mozilla_checks["signature_sha256"]["pass"] += 1
                else:
                    stats["weak_signatures"] += 1
                    mozilla_checks["signature_sha256"]["fail"] += 1

                pk = cert.public_key()
                if isinstance(pk, rsa.RSAPublicKey):
                    if pk.key_size >= 2048:
                        stats["rsa_2048_plus"] += 1
                        mozilla_checks["rsa_key_2048"]["pass"] += 1
                    else:
                        stats["rsa_weak"] += 1
                        mozilla_checks["rsa_key_2048"]["fail"] += 1
                else:
                    stats["ecdsa_keys"] += 1
                    mozilla_checks["rsa_key_2048"]["pass"] += 1

                if meta.get("is_expired"):
                    stats["expired"] += 1
                    mozilla_checks["not_expired"]["fail"] += 1
                else:
                    mozilla_checks["not_expired"]["pass"] += 1
                    days = meta.get("days_until_expiry") or 0
                    if days <= 30:
                        stats["expiring_30d"] += 1
                    else:
                        stats["valid_long_term"] += 1

                lifetime = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
                if lifetime <= 825:
                    mozilla_checks["validity_under_825_days"]["pass"] += 1
                else:
                    mozilla_checks["validity_under_825_days"]["fail"] += 1
            except Exception:
                continue

        nist_score = 0
        total_checks = len(mozilla_checks) * max(len(certs), 1)
        passed = sum(c["pass"] for c in mozilla_checks.values())
        if certs:
            nist_score = round((passed / (len(mozilla_checks) * len(certs))) * 100, 1)

        return {
            **scan,
            "guidelines": {
                "mozilla": mozilla_checks,
                "nist_alignment_score": nist_score,
            },
            "algorithm_stats": stats,
        }

    def scan_one(self, cert_id: str) -> Tuple[bool, List[str]]:
        """Scanne un certificat par identifiant."""
        cert, meta = self.storage.load_certificate(cert_id)
        issues = self.scan_certificate(cert, meta)
        return len(issues) == 0, issues
