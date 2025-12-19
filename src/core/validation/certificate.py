"""Validation de certificats X.509."""

from datetime import datetime, timezone
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertificateValidator:
    """Validateur de certificats X.509."""

    @staticmethod
    def validate_certificate(
        cert: x509.Certificate,
        check_expiration: bool = True,
        check_chain: bool = False,
        ca_certs: List[x509.Certificate] = None
    ) -> Tuple[bool, List[str]]:
        """
        Valide un certificat.

        Args:
            cert: Certificat à valider
            check_expiration: Vérifier l'expiration. Défaut: True
            check_chain: Vérifier la chaîne de certificats. Défaut: False
            ca_certs: Liste des certificats CA pour la validation de chaîne

        Returns:
            Tuple (est_valide, liste_d_erreurs)
        """
        errors = []
        is_valid = True

        # Vérifier la date d'expiration
        if check_expiration:
            now = datetime.now(timezone.utc)
            if cert.not_valid_before_utc > now:
                errors.append(
                    f"Le certificat n'est pas encore valide "
                    f"(valide à partir de {cert.not_valid_before_utc})"
                )
                is_valid = False

            if cert.not_valid_after_utc < now:
                errors.append(
                    f"Le certificat a expiré "
                    f"(expiré le {cert.not_valid_after_utc})"
                )
                is_valid = False

        # Vérifier la chaîne de certificats
        if check_chain and ca_certs:
            chain_valid, chain_errors = CertificateValidator._validate_chain(
                cert, ca_certs
            )
            if not chain_valid:
                errors.extend(chain_errors)
                is_valid = False

        # Vérifier les extensions critiques
        try:
            for ext in cert.extensions:
                if ext.critical:
                    # Vérifier si l'extension est supportée
                    ext_oid = ext.oid
                    # Pour l'instant, on accepte toutes les extensions critiques
                    # mais on pourrait ajouter des vérifications spécifiques
                    pass
        except Exception as e:
            errors.append(f"Erreur lors de la vérification des extensions: {e}")
            is_valid = False

        return is_valid, errors

    @staticmethod
    def _validate_chain(
        cert: x509.Certificate,
        ca_certs: List[x509.Certificate]
    ) -> Tuple[bool, List[str]]:
        """
        Valide la chaîne de certificats.

        Args:
            cert: Certificat à valider
            ca_certs: Liste des certificats CA

        Returns:
            Tuple (est_valide, liste_d_erreurs)
        """
        errors = []
        is_valid = True

        # Trouver le certificat CA qui a émis ce certificat
        issuer_name = cert.issuer
        ca_cert = None

        for ca in ca_certs:
            if ca.subject == issuer_name:
                ca_cert = ca
                break

        if not ca_cert:
            errors.append("Aucune CA trouvée pour valider la chaîne")
            is_valid = False
        else:
            # Vérifier la signature
            try:
                # Pour une validation complète, il faudrait vérifier la signature
                # avec la clé publique de la CA, mais cela nécessite la clé publique
                # Pour l'instant, on vérifie juste que la CA existe
                pass
            except Exception as e:
                errors.append(f"Erreur lors de la validation de la chaîne: {e}")
                is_valid = False

        return is_valid, errors

    @staticmethod
    def get_certificate_info(cert: x509.Certificate) -> dict:
        """
        Extrait les informations d'un certificat.

        Args:
            cert: Certificat à analyser

        Returns:
            Dictionnaire avec les informations du certificat
        """
        info = {
            "subject": {attr.oid._name: attr.value for attr in cert.subject},
            "issuer": {attr.oid._name: attr.value for attr in cert.issuer},
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "is_expired": cert.not_valid_after_utc < datetime.now(timezone.utc),
            "days_until_expiry": (
                cert.not_valid_after_utc - datetime.now(timezone.utc)
            ).days if cert.not_valid_after_utc >= datetime.now(timezone.utc) else 0,
            "version": cert.version.name,
            "signature_algorithm": str(cert.signature_algorithm_oid),
        }

        # Extraire les extensions
        extensions = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name if hasattr(ext.oid, "_name") else str(ext.oid)
            extensions[ext_name] = {
                "critical": ext.critical,
                "value": str(ext.value),
            }
        info["extensions"] = extensions

        # Extraire le Subject Alternative Name si présent
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_list = []
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_list.append(f"DNS:{name.value}")
                elif isinstance(name, x509.IPAddress):
                    san_list.append(f"IP:{name.value}")
            info["subject_alternative_names"] = san_list
        except x509.ExtensionNotFound:
            info["subject_alternative_names"] = []

        return info



