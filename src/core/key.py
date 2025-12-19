"""Gestion des clés cryptographiques."""

from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class KeyManager:
    """Gestionnaire de clés cryptographiques."""

    @staticmethod
    def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
        """
        Génère une clé privée RSA.

        Args:
            key_size: Taille de la clé en bits (2048, 4096). Défaut: 2048

        Returns:
            Clé privée RSA

        Raises:
            ValueError: Si la taille de clé n'est pas valide
        """
        if key_size not in [2048, 3072, 4096]:
            raise ValueError(f"Taille de clé invalide: {key_size}. Utilisez 2048, 3072 ou 4096")

        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def generate_ec_key(curve: str = "secp256r1") -> ec.EllipticCurvePrivateKey:
        """
        Génère une clé privée ECDSA.

        Args:
            curve: Courbe elliptique à utiliser. Défaut: secp256r1

        Returns:
            Clé privée ECDSA

        Raises:
            ValueError: Si la courbe n'est pas valide
        """
        curve_map = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
        }

        if curve not in curve_map:
            raise ValueError(
                f"Courbe invalide: {curve}. "
                f"Utilisez: {', '.join(curve_map.keys())}"
            )

        return ec.generate_private_key(
            curve_map[curve],
            backend=default_backend()
        )

    @staticmethod
    def key_to_pem(
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        password: Optional[bytes] = None
    ) -> bytes:
        """
        Convertit une clé privée en format PEM.

        Args:
            private_key: Clé privée à convertir
            password: Mot de passe optionnel pour chiffrer la clé

        Returns:
            Clé au format PEM (bytes)
        """
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    @staticmethod
    def pem_to_key(pem_data: bytes, password: Optional[bytes] = None):
        """
        Charge une clé privée depuis un format PEM.

        Args:
            pem_data: Données PEM de la clé
            password: Mot de passe si la clé est chiffrée

        Returns:
            Clé privée (RSA ou ECDSA)
        """
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

