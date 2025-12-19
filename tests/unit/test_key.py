"""Tests pour le module key."""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from src.core.key import KeyManager


class TestKeyManager:
    """Tests pour KeyManager."""

    def test_generate_rsa_key_2048(self):
        """Test génération clé RSA 2048 bits."""
        key = KeyManager.generate_rsa_key(2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_generate_rsa_key_4096(self):
        """Test génération clé RSA 4096 bits."""
        key = KeyManager.generate_rsa_key(4096)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096

    def test_generate_rsa_key_invalid_size(self):
        """Test génération clé RSA avec taille invalide."""
        with pytest.raises(ValueError):
            KeyManager.generate_rsa_key(1024)

    def test_generate_ec_key_secp256r1(self):
        """Test génération clé ECDSA secp256r1."""
        key = KeyManager.generate_ec_key("secp256r1")
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_generate_ec_key_invalid_curve(self):
        """Test génération clé ECDSA avec courbe invalide."""
        with pytest.raises(ValueError):
            KeyManager.generate_ec_key("invalid")

    def test_key_to_pem_rsa(self):
        """Test conversion clé RSA en PEM."""
        key = KeyManager.generate_rsa_key(2048)
        pem = KeyManager.key_to_pem(key)
        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_key_to_pem_ec(self):
        """Test conversion clé ECDSA en PEM."""
        key = KeyManager.generate_ec_key()
        pem = KeyManager.key_to_pem(key)
        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem

    def test_pem_to_key_rsa(self):
        """Test chargement clé RSA depuis PEM."""
        key = KeyManager.generate_rsa_key(2048)
        pem = KeyManager.key_to_pem(key)
        loaded_key = KeyManager.pem_to_key(pem)
        assert isinstance(loaded_key, rsa.RSAPrivateKey)
        assert loaded_key.key_size == key.key_size

