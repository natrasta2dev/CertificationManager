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

    def scan_one(self, cert_id: str) -> Tuple[bool, List[str]]:
        """Scanne un certificat par identifiant."""
        cert, meta = self.storage.load_certificate(cert_id)
        issues = self.scan_certificate(cert, meta)
        return len(issues) == 0, issues
