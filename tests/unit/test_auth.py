"""Tests pour l'authentification."""

import pytest

from src.core.auth import create_access_token, hash_password, verify_password
from src.core.users import UserManager, UserRole


class TestAuth:
    """Tests auth et users."""

    def test_password_hash_and_verify(self):
        hashed = hash_password("secret-password")
        assert verify_password("secret-password", hashed)
        assert not verify_password("wrong", hashed)

    def test_create_and_authenticate_user(self, temp_storage, monkeypatch):
        monkeypatch.setenv("CERTMANAGER_STORAGE_PATH", str(temp_storage.storage_path))
        from src.config.settings import get_settings
        get_settings.cache_clear()

        manager = UserManager(storage_path=temp_storage.storage_path)
        manager.create_user("alice", "pass123", UserRole.OPERATOR)

        user = manager.authenticate("alice", "pass123")
        assert user is not None
        assert user.role == UserRole.OPERATOR

        assert manager.authenticate("alice", "wrong") is None

    def test_jwt_token_roundtrip(self, monkeypatch):
        monkeypatch.setenv("CERTMANAGER_JWT_SECRET", "test-secret-key-minimum-32-chars-long")
        from src.config.settings import get_settings
        from src.core.auth import decode_access_token
        get_settings.cache_clear()

        token = create_access_token({"sub": "user-123", "role": "admin"})
        payload = decode_access_token(token)
        assert payload["sub"] == "user-123"

    def test_ensure_default_admin(self, temp_storage, monkeypatch):
        monkeypatch.setenv("CERTMANAGER_STORAGE_PATH", str(temp_storage.storage_path))
        from src.config.settings import get_settings
        get_settings.cache_clear()

        manager = UserManager(storage_path=temp_storage.storage_path)
        admin = manager.ensure_default_admin("admin-pass")
        assert admin is not None
        assert admin.username == "admin"
        assert manager.ensure_default_admin("other") is None
